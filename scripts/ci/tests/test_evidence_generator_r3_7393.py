#!/usr/bin/env python3
"""PR #7393 round 3: gate fixtures for the delta r2 review findings on the vendored certification evidence generator.

  #7437  check_run proves every PLANNED leg has a section, a _DONE row and an EXIT row (MEDIUM)
  #7438  strict row grammar: 0.5, -9, an empty value and a leading + are refused, never read as green
  #7439  the expiry gate comes only from the tip blob (no .sh fallback, no symlink, no skip-worktree copy)
  #7440  --outd gets the same tmp / tmpfs refusal as the CERT_* paths
  #7441  wrapper / flock / timeout are preflighted before any leg; the CONFIG row records source=
  #7442  /proc/mounts octal escapes are decoded before the tmpfs comparison
  #7443  prep.py refuses an empty FED id set
  #7444  bootstrap-log sanitization covers every recorded path; the leak scan covers the CONFIG row paths
  #7446  the run_cert docstring is accurate (ionice only when installed, exit 64, RED launch row with 127)

Scratch lives under .local-runs/ (never a tmpfs).

Run: python3 -m unittest discover -s scripts/ci/tests -p test_evidence_generator_r3_7393.py
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

from test_evidence_generator_5040_5042 import CHAIN_SECTION, EVIDENCE, TIP, ScratchCase, load
from test_evidence_generator_r2_7393 import EXPIRY_PY, EXPIRY_SH, GIT, make_repo

CONFIG = ("CONFIG cargo_slot=none slot_lock=none targets=/data/cert-t tmpdir=/data/cert-d outd=/data/cert-o "
          "sources=cargo_slot:default,slot_lock:default,targets:arg,tmpdir:arg,outd:arg")


def block(leg, legs, body, exit_row=True, plan=True):
    text = CONFIG + "\n"
    if plan:
        text += f"PLAN leg={leg} legs={','.join(legs)}\n"
    text += body
    if exit_row:
        text += f"EXIT=0 leg={leg} aggregate_failures=0 12:00Z\n"
    return text


SEC = {"battery": "== CERT LEGS 10:00Z HEAD=x host=Linux 7.0 umask 022 wt=755\n",
       "removal": "== removal proof 10:30Z cargo=/usr/bin/cargo\n",
       "pg": "== pg coverage leg 10:40Z\n",
       "bootstrap": "== bootstrap-cert-gate (self-build) 10:45Z\n"}
DONE = {"battery": "BATTERY_DONE aggregate_failures=0 10:20Z\n", "removal": "RP_DONE aggregate_failures=0\n",
        "pg": "PG_DONE aggregate_failures=0 10:41Z\n", "bootstrap": "BCG_DONE aggregate_failures=0 10:50Z\n"}
CHAIN_LEGS = ("battery", "removal", "pg", "bootstrap", "chain")


def leg_text(leg):
    return SEC[leg] + DONE[leg]


GREEN_CHAIN = block("chain", CHAIN_LEGS, "".join(leg_text(l) for l in CHAIN_LEGS[:-1])
                    + "CHAIN_DONE aggregate_failures=0 10:55Z\n")


class PlannedLegs7437(ScratchCase):
    def setUp(self):
        super().setUp()
        self.bb = load("build_bundle")

    def refused(self, text):
        with self.assertRaises(self.bb.Fatal):
            self.bb.check_run(self.legs(text))

    def test_green_planned_chain_is_accepted_7437(self):
        self.bb.check_run(self.legs(GREEN_CHAIN))

    def test_finished_green_standalone_leg_after_a_green_chain_is_accepted_7437(self):
        for leg in ("removal", "pg", "bootstrap"):
            with self.subTest(leg=leg):
                self.bb.check_run(self.legs(GREEN_CHAIN + block(leg, (leg,), leg_text(leg))))

    def test_killed_standalone_leg_after_a_green_chain_is_refused_7437(self):
        for leg in ("removal", "pg", "bootstrap"):
            with self.subTest(leg=leg):
                self.refused(GREEN_CHAIN + block(leg, (leg,), SEC[leg], exit_row=False))

    def test_standalone_leg_with_a_section_and_done_but_no_exit_row_is_refused_7437(self):
        for leg in ("removal", "pg", "bootstrap"):
            with self.subTest(leg=leg):
                self.refused(GREEN_CHAIN + block(leg, (leg,), leg_text(leg), exit_row=False))

    def test_standalone_leg_with_an_exit_row_but_no_done_row_is_refused_7437(self):
        for leg in ("removal", "pg", "bootstrap"):
            with self.subTest(leg=leg):
                self.refused(GREEN_CHAIN + block(leg, (leg,), SEC[leg]))

    def test_planned_leg_missing_from_the_chain_is_refused_7437(self):
        for missing in ("battery", "removal", "pg", "bootstrap"):
            with self.subTest(missing=missing):
                body = "".join(leg_text(l) for l in CHAIN_LEGS[:-1] if l != missing) + "CHAIN_DONE aggregate_failures=0 10:55Z\n"
                self.refused(block("chain", CHAIN_LEGS, body))

    def test_chain_killed_after_a_green_chain_is_refused_7437(self):
        self.refused(GREEN_CHAIN + block("chain", CHAIN_LEGS, leg_text("battery"), exit_row=False))

    def test_block_without_a_plan_row_is_refused_7437(self):
        self.refused(block("chain", CHAIN_LEGS, "".join(leg_text(l) for l in CHAIN_LEGS[:-1])
                           + "CHAIN_DONE aggregate_failures=0 10:55Z\n", plan=False))

    def test_malformed_plan_row_is_refused_7437(self):
        self.refused(GREEN_CHAIN.replace("PLAN leg=chain legs=", "PLAN leg=chain legz="))

    def test_two_exit_rows_in_one_block_are_refused_7437(self):
        self.refused(GREEN_CHAIN + "EXIT=0 leg=chain aggregate_failures=0 12:01Z\n")

    def test_run_cert_writes_the_plan_row_and_a_pg_section_7437(self):
        rc = load("run_cert")
        self.assertEqual(rc.PLANS["chain"], ("battery", "removal", "pg", "bootstrap", "chain"))
        for leg in ("battery", "removal", "pg", "bootstrap"):
            self.assertEqual(rc.PLANS[leg], (leg,))
        wt, tip = make_repo(self.dir / "repo")
        r = rc.Run(argparse.Namespace(tip=tip, wt=str(wt), outd=str(self.dir / "o"), leg="pg",
                                      targets=str(self.dir / "t"), tmpdir=str(self.dir / "tmp")))
        self.assertEqual(r.plan_row("pg"), "PLAN leg=pg legs=pg")
        with mock.patch.object(r, "run", return_value=0), mock.patch.object(r, "check_test"), \
                contextlib.redirect_stdout(io.StringIO()):
            r.pg()
        self.assertIn("== pg coverage", (self.dir / "o" / "legs.log").read_text())


class StrictGrammar7438(ScratchCase):
    def setUp(self):
        super().setUp()
        self.bb = load("build_bundle")

    def refused(self, text):
        with self.assertRaises(self.bb.Fatal):
            self.bb.check_run(self.legs(text))

    def test_fractional_chain_done_is_refused_7438(self):
        self.refused(CHAIN_SECTION.replace("CHAIN_DONE aggregate_failures=0", "CHAIN_DONE aggregate_failures=0.5"))

    def test_fractional_and_comma_leg_aggregates_are_refused_7438(self):
        for bad in ("0.5", "0,3", "00x"):
            with self.subTest(value=bad):
                self.refused(CHAIN_SECTION.replace("BATTERY_DONE aggregate_failures=0", f"BATTERY_DONE aggregate_failures={bad}"))

    def test_negative_exit_row_is_refused_7438(self):
        for bad in ("-1", "-9"):
            with self.subTest(value=bad):
                self.refused(CHAIN_SECTION + f"EXIT={bad} leg=pg aggregate_failures=0 11:00Z\n")

    def test_negative_aggregate_is_refused_7438(self):
        self.refused(CHAIN_SECTION.replace("CHAIN_DONE aggregate_failures=0", "CHAIN_DONE aggregate_failures=-1"))
        self.refused(CHAIN_SECTION + "EXIT=0 leg=pg aggregate_failures=-9 11:00Z\n")

    def test_empty_value_is_refused_7438(self):
        self.refused(CHAIN_SECTION.replace("CHAIN_DONE aggregate_failures=0", "CHAIN_DONE aggregate_failures="))
        self.refused(CHAIN_SECTION + "EXIT= leg=pg aggregate_failures=0 11:00Z\n")
        self.refused(CHAIN_SECTION + "EXIT=0 leg=pg aggregate_failures= 11:00Z\n")

    def test_leading_plus_is_refused_7438(self):
        self.refused(CHAIN_SECTION.replace("CHAIN_DONE aggregate_failures=0", "CHAIN_DONE aggregate_failures=+0"))
        self.refused(CHAIN_SECTION + "EXIT=+1 leg=pg aggregate_failures=0 11:00Z\n")
        self.refused(CHAIN_SECTION + "PG_DONE aggregate_failures=+0 11:00Z\n")

    def test_done_row_without_the_aggregate_field_is_refused_7438(self):
        self.refused(CHAIN_SECTION + "PG_DONE 11:00Z\n")
        self.refused(CHAIN_SECTION + "EXIT=0 leg=pg\n")

    def test_the_runner_own_rows_still_pass_7438(self):
        self.bb.check_run(self.legs(CHAIN_SECTION + "EXIT=0 leg=chain aggregate_failures=0 11:00Z\n"))


class ExpiryFromTheBlob7439(ScratchCase):
    def make(self, files=None, symlink=None):
        rc = load("run_cert")
        wt, tip = make_repo(self.dir / "repo", files)
        if symlink:
            (wt / "scripts").mkdir(exist_ok=True)
            (wt / "outside.py").write_text("raise SystemExit(0)\n")
            os.symlink("../outside.py", wt / symlink)
            subprocess.run([*GIT, "add", symlink], cwd=wt, check=True)
            subprocess.run([*GIT, "add", "outside.py"], cwd=wt, check=True)
            subprocess.run([*GIT, "commit", "-q", "-m", "link"], cwd=wt, check=True)
        r = rc.Run(argparse.Namespace(tip=tip, wt=str(wt), outd=str(self.dir / "o"), leg="gates",
                                      targets=str(self.dir / "t"), tmpdir=str(self.dir / "tmp")))
        return rc, r, wt

    def test_untracked_sh_with_nothing_tracked_is_refused_7439(self):
        rc, r, wt = self.make()
        (wt / "scripts").mkdir()
        (wt / EXPIRY_SH).write_text("exit 0\n")
        with self.assertRaises(FileNotFoundError):
            r.expiry_gate()

    def test_tracked_sh_alone_is_never_a_fallback_7439(self):
        rc, r, wt = self.make({EXPIRY_SH: "exit 0\n"})
        with self.assertRaises(FileNotFoundError):
            r.expiry_gate()

    def test_tracked_symlink_is_refused_7439(self):
        rc, r, wt = self.make(symlink=EXPIRY_PY)
        with self.assertRaises(ValueError):
            r.expiry_gate()

    def test_skip_worktree_copy_never_runs_the_blob_is_what_runs_7439(self):
        rc, r, wt = self.make({EXPIRY_PY: "BLOB = 1\n"})
        subprocess.run(["git", "update-index", "--skip-worktree", EXPIRY_PY], cwd=wt, check=True)
        (wt / EXPIRY_PY).write_text("BLOB = 'MODIFIED DISK COPY'\n")
        self.assertEqual(r.dirty_tracked(), [])  # the hiding the review reproduced
        argv, data, sha = r.expiry_gate()
        self.assertEqual(argv[:2], [sys.executable, "-I"])
        self.assertEqual(data, b"BLOB = 1\n")  # the HEAD blob, not the modified disk copy
        blob = subprocess.run(["git", "rev-parse", f"HEAD:{EXPIRY_PY}"], cwd=wt, capture_output=True, text=True).stdout.strip()
        self.assertEqual(sha, blob)

    def test_recapture_symlink_is_refused_and_the_blob_sha_is_returned_7439(self):
        rc = load("run_cert")
        wt, tip = make_repo(self.dir / "repo", {"scripts/recapture-cert-3607-posture.py": "x = 1\n"})
        rel, src, sha = rc.recapture_blob(wt, tip)
        self.assertEqual((rel, src), ("scripts/recapture-cert-3607-posture.py", "x = 1\n"))
        self.assertEqual(len(sha), 40)
        wt2, tip2 = make_repo(self.dir / "repo2")
        (wt2 / "scripts").mkdir()
        os.symlink("../README", wt2 / "scripts/recapture-cert-3607-posture.py")
        subprocess.run([*GIT, "add", "scripts"], cwd=wt2, check=True)
        subprocess.run([*GIT, "commit", "-q", "-m", "link"], cwd=wt2, check=True)
        tip2 = subprocess.run(["git", "rev-parse", "HEAD"], cwd=wt2, capture_output=True, text=True).stdout.strip()
        with self.assertRaises(ValueError):
            rc.recapture_blob(wt2, tip2)


class OutdAndConfig7440(ScratchCase):
    def ns(self, **kw):
        base = dict(tip=TIP, wt=str(self.dir), outd=str(self.dir / "o"), leg="chain",
                    targets=str(self.dir / "t"), tmpdir=str(self.dir / "tmp"))
        base.update(kw)
        return argparse.Namespace(**base)

    def test_outd_on_a_tmp_root_is_refused_and_nothing_is_written_7440(self):
        rc = load("run_cert")
        fake = self.dir / "faketmp"  # #7492: a fake tmp root inside the scratch dir, never a real one
        with mock.patch.object(rc, "TMP_ROOTS", (str(fake),)):
            for bad in (fake / "r3-outd", fake / "deeper" / "r3-outd"):
                with self.subTest(path=str(bad)):
                    with self.assertRaises(rc.ConfigError):
                        rc.Run(self.ns(outd=str(bad)))
                    self.assertFalse(bad.exists())

    def test_outd_on_a_tmpfs_mount_is_refused_7440(self):
        rc = load("run_cert")
        with mock.patch.object(rc, "is_tmpfs_path", side_effect=lambda p, mounts=None: str(p).endswith("/o")):
            with self.assertRaises(rc.ConfigError):
                rc.Run(self.ns())

    def test_main_exits_64_for_a_tmp_outd_7440(self):
        rc = load("run_cert")
        fake = self.dir / "faketmp"
        argv = ["run_cert.py", "chain", "--tip", TIP, "--wt", str(self.dir), "--outd", str(fake / "r3-outd-main"),
                "--targets", str(self.dir / "t"), "--tmpdir", str(self.dir / "tmp")]
        with mock.patch.object(rc, "TMP_ROOTS", (str(fake),)), mock.patch.object(sys, "argv", argv), \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(rc.main(), 64)
        self.assertFalse((fake / "r3-outd-main").exists())


class Preflight7441(ScratchCase):
    def ns(self, **kw):
        base = dict(tip=TIP, wt=str(self.dir), outd=str(self.dir / "o"), leg="chain",
                    targets=str(self.dir / "t"), tmpdir=str(self.dir / "tmp"))
        base.update(kw)
        return argparse.Namespace(**base)

    def test_missing_wrapper_is_refused_before_any_leg_7441(self):
        rc = load("run_cert")
        r = rc.Run(self.ns(cargo_slot=str(self.dir / "no-such-wrapper")))
        with self.assertRaises(rc.ConfigError) as cm:
            r.preflight()
        self.assertIn("no-such-wrapper", str(cm.exception))

    def test_relative_missing_wrapper_is_refused_7441(self):
        rc = load("run_cert")
        r = rc.Run(self.ns(cargo_slot="relative-not-there"))
        with self.assertRaises(rc.ConfigError):
            r.preflight()

    def test_non_executable_and_directory_wrappers_are_refused_7441(self):
        rc = load("run_cert")
        plain = self.dir / "plain"
        plain.write_text("#!/bin/sh\n")
        plain.chmod(0o644)
        for bad in (plain, self.dir):
            with self.subTest(path=str(bad)):
                with self.assertRaises(rc.ConfigError):
                    rc.Run(self.ns(cargo_slot=str(bad))).preflight()

    def test_executable_wrapper_passes_7441(self):
        rc = load("run_cert")
        ok = self.dir / "slot"
        ok.write_text("#!/bin/sh\n")
        ok.chmod(0o755)
        rc.Run(self.ns(cargo_slot=str(ok))).preflight()

    def test_missing_flock_with_a_slot_lock_and_missing_timeout_are_refused_7441(self):
        rc = load("run_cert")
        real = rc.shutil.which
        with mock.patch.object(rc.shutil, "which", side_effect=lambda n, *a: None if n == "flock" else real(n, *a)):
            with self.assertRaises(rc.ConfigError):
                rc.Run(self.ns(slot_lock=str(self.dir / "lock"))).preflight()
            rc.Run(self.ns()).preflight()  # no slot lock: flock is not needed
        with mock.patch.object(rc.shutil, "which", side_effect=lambda n, *a: None if n == "timeout" else real(n, *a)):
            with self.assertRaises(rc.ConfigError):
                rc.Run(self.ns()).preflight()

    def test_gates_leg_needs_neither_wrapper_nor_timeout_7441(self):
        rc = load("run_cert")
        with mock.patch.object(rc.shutil, "which", return_value=None):
            rc.Run(self.ns(leg="gates", cargo_slot=str(self.dir / "no-such-wrapper"))).preflight()

    def test_config_row_records_where_each_value_came_from_7441(self):
        rc = load("run_cert")
        env = {"CERT_TARGETS": str(self.dir / "et")}
        with mock.patch.dict(os.environ, env):
            r = rc.Run(self.ns(targets="", tmpdir=str(self.dir / "tmp"), cargo_slot=""))
        row = r.config_row()
        self.assertIn("sources=", row)
        self.assertIn("targets:env", row)
        self.assertIn("tmpdir:arg", row)
        self.assertIn("cargo_slot:default", row)
        self.assertIn("outd:arg", row)

    def test_main_refuses_a_missing_wrapper_with_rows_and_no_traceback_7441(self):
        rc = load("run_cert")
        wt, tip = make_repo(self.dir / "repo")
        outd = self.dir / "o2"
        argv = ["run_cert.py", "chain", "--tip", tip, "--wt", str(wt), "--outd", str(outd),
                "--targets", str(self.dir / "t"), "--tmpdir", str(self.dir / "tmp"),
                "--cargo-slot", str(self.dir / "no-such-wrapper")]
        err, out = io.StringIO(), io.StringIO()
        with mock.patch.object(sys, "argv", argv), contextlib.redirect_stderr(err), contextlib.redirect_stdout(out):
            code = rc.main()
        self.assertEqual(code, 64)
        self.assertNotIn("Traceback", err.getvalue() + out.getvalue())
        self.assertIn("no-such-wrapper", err.getvalue())
        text = (outd / "legs.log").read_text()
        self.assertIn("  RED preflight", text)
        self.assertIn("EXIT=64 leg=chain", text)  # #7490: the row records the exit code the process returns
        self.assertNotIn("\n== ", text)  # no leg started
        bb = load("build_bundle")
        with self.assertRaises(bb.Fatal):
            bb.check_run(outd)


class MountEscapes7442(GuardedCase):
    def test_octal_escaped_mount_point_is_decoded_7442(self):
        rc = load("run_cert")
        mounts = "tmpfs /mnt/my\\040ram tmpfs rw 0 0\n/dev/sda1 / ext4 rw 0 0\n"
        self.assertTrue(rc.is_tmpfs_path("/mnt/my ram/x", mounts))
        self.assertFalse(rc.is_tmpfs_path("/mnt/my/ram", mounts))

    def test_tab_newline_and_backslash_escapes_are_decoded_7442(self):
        rc = load("run_cert")
        for esc, ch in (("\\011", "\t"), ("\\012", "\n"), ("\\134", "\\")):
            with self.subTest(esc=esc):
                mounts = f"tmpfs /mnt/a{esc}b tmpfs rw 0 0\n"
                self.assertTrue(rc.is_tmpfs_path(f"/mnt/a{ch}b/x", mounts))


class EmptyFedSet7443(ScratchCase):
    def run_prep(self, wt, tip):
        prep = load("prep")
        argv = ["prep.py", "--repo", str(wt), "--base", tip, "--tip", tip]
        err, out = io.StringIO(), io.StringIO()
        with mock.patch.object(sys, "argv", argv), contextlib.redirect_stderr(err), contextlib.redirect_stdout(out):
            try:
                code = prep.main()
            except SystemExit as e:
                code = e.code
        return code, err.getvalue(), out.getvalue()

    def test_empty_fed_set_is_an_exit_3_naming_the_rev_7443(self):
        wt, tip = make_repo(self.dir / "repo", {"src/a.rs": "fn main() {}\n"})
        code, err, _out = self.run_prep(wt, tip)
        self.assertEqual(code, 3)
        self.assertIn(tip, err)
        self.assertIn("AI_MEMORY_FED_", err)

    def test_non_empty_sets_are_a_normal_measurement_7443(self):
        wt, tip = make_repo(self.dir / "repo", {"src/a.rs": 'const X: &str = "AI_MEMORY_FED_ONE";\n'})
        code, _err, out = self.run_prep(wt, tip)
        self.assertEqual(code, 0)
        self.assertIn("FED_IDS base=1 tip=1", out)


class Sanitize7444(ScratchCase):
    def test_typed_and_resolved_worktree_forms_are_both_replaced_7444(self):
        bb = load("build_bundle")
        text = "building in /link/wt-x/target and /real/wt-x/target\n"
        out = bb.sanitize_paths(text, ["/real/wt-x", "/link/wt-x"], [])
        self.assertNotIn("/link/wt-x", out)
        self.assertNotIn("/real/wt-x", out)
        self.assertEqual(out.count("<repo-root>"), 2)

    def test_config_row_paths_are_sanitized_and_scanned_7444(self):
        bb = load("build_bundle")
        outd = self.legs(CONFIG + "\nPLAN leg=chain legs=battery\n")
        cfg = bb.config_paths(outd)
        for p in ("/data/cert-t", "/data/cert-d", "/data/cert-o"):
            with self.subTest(path=p):
                self.assertIn(p, cfg)
        pats = bb.leak_patterns(Path("/wt-x"), Path("/out-x"), config=cfg)
        for p in cfg:
            self.assertIn(p, pats)
        out = bb.sanitize_paths("cargo wrote /data/cert-t/cert7-sal/x and /data/cert-d/y\n", [], cfg)
        self.assertNotIn("/data/cert-", out)

    def test_every_config_row_of_the_log_is_read_7444(self):
        bb = load("build_bundle")
        second = CONFIG.replace("/data/cert-t", "/data/second-t")
        outd = self.legs(CONFIG + "\n" + second + "\n")
        cfg = bb.config_paths(outd)
        self.assertIn("/data/cert-t", cfg)
        self.assertIn("/data/second-t", cfg)

    def test_none_placeholders_are_not_paths_7444(self):
        bb = load("build_bundle")
        cfg = bb.config_paths(self.legs(CONFIG + "\n"))
        self.assertNotIn("none", cfg)


class Docstring7446(GuardedCase):
    def test_docstring_is_accurate_7446(self):
        doc = (EVIDENCE / "run_cert.py").read_text().split('"""')[1]
        self.assertIn("ionice -c3 when installed", doc)
        self.assertIn("exit 64", doc)
        self.assertIn("127", doc)
        self.assertNotIn("nice 15, ionice -c3;", doc)


if __name__ == "__main__":
    unittest.main()
