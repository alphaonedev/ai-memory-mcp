#!/usr/bin/env python3
"""PR #7393 round 2: gate fixtures for the review findings on the vendored certification evidence generator.

  #7419  check_run judges EVERY chain section and every aggregate row (HIGH)
  #7420  a missing cargo-slot wrapper / flock / timeout is a RED row + EXIT row, not a traceback
  #7421  CERT_* overrides anchor to the checkout, are refused on a tmpfs, and the wrapper is recorded (with #7413)
  #7422  a failed git push in the gates leg is a failure
  #7411  recapture / expiry scripts come from the tip TREE, never an untracked or modified file
  #7412  --outd is quoted safely in the generated bash
  #7415  the leak scan covers /Users/, /Volumes/, /var/folders/, /root/ and the resolved run paths
  #7423  prep.fed_ids checks the git grep return code
  #7425  the cert-alone.out header states ionice only when it was used
  #7417  prep.py docstring names the Python expiry gate; FED_ID spacing restored

Scratch lives under .local-runs/ (never a tmpfs).

Run: python3 -m unittest discover -s scripts/ci/tests -p test_evidence_generator_r2_7393.py
"""
import argparse
import contextlib
import io
import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

from tmp_runtime_guard_7393 import GuardedCase
import unittest.mock as mock

from test_evidence_generator_5040_5042 import CHAIN_SECTION, EVIDENCE, REPO, TIP, ScratchCase, load

RECAPTURE_PY = "scripts/recapture-cert-3607-posture.py"
RECAPTURE_SH = "scripts/recapture-cert-3607-posture.sh"
EXPIRY_PY = "scripts/check_cert_expiry.py"
EXPIRY_SH = "scripts/check-cert-expiry.sh"
SH_BODY = (
    "#!/usr/bin/env bash\n"
    'ROOT="$(cd "$(dirname "$0")/.." && pwd)"\n'
    'OUT="$ROOT/docs/compliance/evidence/cert-3607"\n'
    'FIX="$ROOT/.local-runs/cert-3607-fixtures"\n'
    'printf %s "$OUT"\n'
)
GIT = ["git", "-c", "user.name=fixture", "-c", "user.email=" + "@".join(("fixture", "fixture.test")),
       "-c", "commit.gpgsign=false"]


def make_repo(root, files=None):
    root.mkdir(parents=True)
    subprocess.run([*GIT, "init", "-q"], cwd=root, check=True)
    (root / "README").write_text("x\n")
    for rel, body in (files or {}).items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(body)
    subprocess.run([*GIT, "add", "-A"], cwd=root, check=True)
    subprocess.run([*GIT, "commit", "-q", "-m", "fixture"], cwd=root, check=True)
    tip = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True, check=True).stdout.strip()
    return root, tip


def second_chain(tail):
    return f"== CERT LEGS 11:00Z HEAD={TIP} host=Linux 7.0.11 umask 022 wt=755\n" + tail


class CheckRunEverySection7419(ScratchCase):
    def setUp(self):
        super().setUp()
        self.bb = load("build_bundle")

    def refused(self, text):
        with self.assertRaises(self.bb.Fatal):
            self.bb.check_run(self.legs(text))

    def test_green_then_nonzero_chain_done_is_refused_7419(self):
        self.refused(CHAIN_SECTION + "CHAIN_DONE aggregate_failures=1 11:00Z\n")

    def test_chain_done_zero_then_three_without_a_row_is_refused_7419(self):
        self.refused(CHAIN_SECTION + "CHAIN_DONE aggregate_failures=3 11:00Z\n")

    def test_exit_row_after_the_chain_is_refused_7419(self):
        self.refused(CHAIN_SECTION + "EXIT=1 leg=chain aggregate_failures=1 11:00Z\n")

    def test_second_chain_started_and_killed_is_refused_7419(self):
        self.refused(CHAIN_SECTION + second_chain("== BUILD_DEFAULT 11:00Z\n"))

    def test_nonzero_leg_aggregate_row_is_refused_7419(self):
        self.refused(CHAIN_SECTION.replace("BATTERY_DONE aggregate_failures=0", "BATTERY_DONE aggregate_failures=2"))
        self.refused(CHAIN_SECTION + "PG_DONE aggregate_failures=1 11:00Z\n")

    def test_two_chain_done_rows_in_one_section_are_refused_7419(self):
        self.refused(CHAIN_SECTION + "CHAIN_DONE aggregate_failures=0 11:00Z\n")

    def test_two_green_chain_sections_are_accepted_7419(self):
        text = CHAIN_SECTION + second_chain(CHAIN_SECTION.split("\n", 1)[1])
        self.assertEqual(len(self.bb.check_run(self.legs(text))), 2)

    def test_missing_chain_done_keeps_its_message_7419(self):
        with self.assertRaisesRegex(self.bb.Fatal, "CHAIN_DONE"):
            self.bb.check_run(self.legs(CHAIN_SECTION.replace("CHAIN_DONE", "CHAIN_STOPPED")))


class MissingWrapper7420(ScratchCase):
    def run_main(self, outd, wt, tip, *extra):
        rc = load("run_cert")
        argv = ["run_cert.py", "chain", "--tip", tip, "--wt", str(wt), "--outd", str(outd),
                "--targets", str(self.dir / "t"), "--tmpdir", str(self.dir / "tmp"), *extra]
        err, out = io.StringIO(), io.StringIO()
        with mock.patch.object(sys, "argv", argv), mock.patch.object(rc, "FLOOR_BUILD_GIB", 0), \
                mock.patch.object(rc, "FLOOR_ROOT_GIB", 0), contextlib.redirect_stderr(err), contextlib.redirect_stdout(out):
            code = rc.main()
        return code, out.getvalue() + err.getvalue()

    def test_missing_cargo_slot_after_a_green_chain_is_refused_not_a_traceback_7420(self):
        wt, tip = make_repo(self.dir / "repo")
        outd = self.dir / "o"
        outd.mkdir()
        (outd / "legs.log").write_text(CHAIN_SECTION)  # the reviewer's live repro: a green chain first
        missing = self.dir / "no-such-wrapper"
        code, output = self.run_main(outd, wt, tip, "--cargo-slot", str(missing))
        self.assertEqual(code, 64)  # #7441: refused by the preflight, before any leg
        self.assertNotIn("Traceback", output)
        self.assertIn("no-such-wrapper", output)  # actionable: names the wrapper that could not start
        text = (outd / "legs.log").read_text()
        self.assertIn("  RED ", text)
        self.assertIn("EXIT=64 leg=chain", text)  # #7490
        self.assertIn(f"CONFIG cargo_slot={missing}", text)  # #7413: the wrapper actually used is recorded
        bb = load("build_bundle")
        with self.assertRaises(bb.Fatal):
            bb.check_run(outd)

    def test_missing_flock_or_timeout_binary_is_a_red_row_not_an_exception_7420(self):
        rc = load("run_cert")
        ns = argparse.Namespace(tip=TIP, wt=str(self.dir), outd=str(self.dir / "o"), leg="chain",
                                targets=str(self.dir / "t"), tmpdir=str(self.dir / "tmp"))
        r = rc.Run(ns)
        with contextlib.redirect_stderr(io.StringIO()):
            code = r.run([str(self.dir / "no-such-flock"), "nice", "x"], self.dir / "out.log", gate=False)
        self.assertEqual(code, 127)
        self.assertEqual(r.bad, 1)
        self.assertIn("  RED ", (self.dir / "o" / "legs.log").read_text())


class Overrides7421(ScratchCase):
    def make(self, **kw):
        rc = load("run_cert")
        return rc, rc.Run(argparse.Namespace(tip=TIP, wt=str(self.dir), outd=str(self.dir / "o"), leg="chain", **kw))

    def chdir_away(self):
        old = os.getcwd()
        os.chdir(self.dir)
        self.addCleanup(os.chdir, old)

    def test_relative_overrides_anchor_to_the_checkout_not_cwd_7421(self):
        self.chdir_away()
        rel_t, rel_d = f".local-runs/{self.dir.name}-t", f".local-runs/{self.dir.name}-d"
        self.addCleanup(shutil.rmtree, str(REPO / rel_t), True)
        self.addCleanup(shutil.rmtree, str(REPO / rel_d), True)
        env = {"CERT_TARGETS": rel_t, "CERT_TMPDIR": rel_d, "CERT_CARGO_SLOT": "wrap/slot", "CERT_SLOT_LOCK": "wrap/lock"}
        with mock.patch.dict(os.environ, env):
            rc, r = self.make()
        self.assertEqual(r.targets, REPO / rel_t)
        self.assertEqual(r.tmpdir, REPO / rel_d)
        self.assertEqual(r.cargo, [str(REPO / "wrap/slot"), "cargo"])
        self.assertEqual(r.slot_lock, str(REPO / "wrap/lock"))

    def test_relative_prep_repo_anchors_to_the_checkout_7421(self):
        self.chdir_away()
        prep = load("prep")
        with mock.patch.dict(os.environ, {"CERT_PREP_REPO": "some/checkout"}):
            self.assertEqual(prep.default_repo(), REPO / "some/checkout")

    def test_tmpfs_overrides_are_refused_7413(self):
        """A fake tmp root under the scratch directory with TMP_ROOTS patched: no real tmp-root path is ever used (#7534)."""
        rc = load("run_cert")
        root = Path(os.path.realpath(self.dir)) / "fake-tmp-root"
        root.mkdir()
        with mock.patch.object(rc, "TMP_ROOTS", (str(root),)):
            for bad in (root / "cert", root, root / "a" / "b"):
                for field in ("targets", "tmpdir"):
                    with self.subTest(path=str(bad), field=field):
                        with self.assertRaises(rc.ConfigError):
                            self.make(**{field: str(bad)})

    def test_tmpfs_mount_detection_7413(self):
        rc = load("run_cert")
        mounts = "tmpfs /srv/ramdisk tmpfs rw 0 0\n/dev/sda1 / ext4 rw 0 0\nramfs /srv/rammount ramfs rw 0 0\n"
        self.assertTrue(rc.is_tmpfs_path("/srv/ramdisk/x", mounts))
        self.assertTrue(rc.is_tmpfs_path("/srv/rammount/user/1000/x", mounts))
        self.assertFalse(rc.is_tmpfs_path("/home/x", mounts))
        self.assertFalse(rc.is_tmpfs_path("/srv/ramdiskx/y", mounts))


class PushFailure7422(ScratchCase):
    def make(self, remote):
        rc = load("run_cert")
        wt, tip = make_repo(self.dir / "repo")
        subprocess.run(["git", "remote", "add", "origin", str(remote)], cwd=wt, check=True)
        r = rc.Run(argparse.Namespace(tip=tip, wt=str(wt), outd=str(self.dir / "o"), leg="gates",
                                      targets=str(self.dir / "t"), tmpdir=str(self.dir / "tmp")))
        return r, tip

    def test_failed_push_counts_as_a_failure_7422(self):
        r, tip = self.make(self.dir / "no-such-remote")
        with contextlib.redirect_stdout(io.StringIO()):
            r.push_gated(tip, "cert-branch")
        self.assertEqual(r.bad, 1)
        self.assertIn("  RED push", (self.dir / "o" / "gates.log").read_text())

    def test_good_push_is_not_a_failure_7422(self):
        remote = self.dir / "remote.git"
        subprocess.run(["git", "init", "-q", "--bare", str(remote)], check=True)
        r, tip = self.make(remote)
        with contextlib.redirect_stdout(io.StringIO()):
            r.push_gated(tip, "cert-branch")
        self.assertEqual(r.bad, 0)


class TipTreeScripts7411(ScratchCase):
    def test_untracked_py_does_not_shadow_the_tracked_sh_7411(self):
        rc = load("run_cert")
        wt, tip = make_repo(self.dir / "repo", {RECAPTURE_SH: SH_BODY})
        (wt / RECAPTURE_PY).write_text("print('untracked look-alike')\n")
        self.assertEqual(rc.pick_recapture(wt, tip), RECAPTURE_SH)

    def test_recapture_body_is_the_tip_blob_not_the_disk_file_7411(self):
        rc = load("run_cert")
        wt, tip = make_repo(self.dir / "repo", {RECAPTURE_SH: SH_BODY})
        (wt / RECAPTURE_SH).write_text("echo modified\n")
        rel, body = rc.recapture_source(wt, tip)
        self.assertEqual((rel, body), (RECAPTURE_SH, SH_BODY))

    def test_nothing_at_the_tip_is_a_file_not_found_naming_both_paths_7411(self):
        rc = load("run_cert")
        wt, tip = make_repo(self.dir / "repo")
        (wt / "scripts").mkdir()
        (wt / RECAPTURE_PY).write_text("print('untracked')\n")
        with self.assertRaises(FileNotFoundError) as cm:
            rc.pick_recapture(wt, tip)
        self.assertIn(RECAPTURE_PY, str(cm.exception))
        self.assertIn(RECAPTURE_SH, str(cm.exception))

    def test_py_at_the_tip_wins_over_sh_7411(self):
        rc = load("run_cert")
        wt, tip = make_repo(self.dir / "repo", {RECAPTURE_PY: "x = 1\n", RECAPTURE_SH: SH_BODY})
        self.assertEqual(rc.pick_recapture(wt, tip), RECAPTURE_PY)

    def test_expiry_gate_is_chosen_from_head_not_the_disk_7411(self):
        rc = load("run_cert")
        wt, tip = make_repo(self.dir / "repo", {EXPIRY_SH: "exit 0\n"})
        (wt / EXPIRY_PY).write_text("raise SystemExit(0)\n")  # untracked look-alike
        r = rc.Run(argparse.Namespace(tip=tip, wt=str(wt), outd=str(self.dir / "o"), leg="gates",
                                      targets=str(self.dir / "t"), tmpdir=str(self.dir / "tmp")))
        with self.assertRaises(FileNotFoundError):  # #7439: the tracked .sh is not a fallback either
            r.expiry_gate()

    def test_expiry_gate_prefers_the_tracked_py_7411(self):
        rc = load("run_cert")
        wt, tip = make_repo(self.dir / "repo", {EXPIRY_PY: "x = 1\n", EXPIRY_SH: "exit 0\n"})
        r = rc.Run(argparse.Namespace(tip=tip, wt=str(wt), outd=str(self.dir / "o"), leg="gates",
                                      targets=str(self.dir / "t"), tmpdir=str(self.dir / "tmp")))
        argv, data, _sha = r.expiry_gate()
        self.assertEqual(argv[:2], [sys.executable, "-I"])
        self.assertEqual(data, b"x = 1\n")  # #7439: the HEAD blob, handed over in memory (#7618)


class ShellRetarget7412(ScratchCase):
    def test_outd_with_space_quote_and_dollar_is_data_not_code_7412(self):
        rc = load("run_cert")
        ev = self.dir / "a b" / "it's $(echo pwn) `x`" / "evidence"
        fix = self.dir / "a b" / "it's" / "fix"
        body, n_out, n_fix = rc.retarget_shell(SH_BODY, ev, fix)
        self.assertEqual((n_out, n_fix), (1, 1))
        script = self.dir / "t.sh"
        script.write_text(body)
        out = subprocess.run(["bash", str(script)], capture_output=True, text=True).stdout
        self.assertEqual(out, str(ev))

    def test_outd_with_backslash_does_not_break_the_python_form_7412(self):
        rc = load("run_cert")
        ev, fix = Path("/x/a\\1b/evidence"), Path("/x/fix")
        body, n_out, n_fix = rc.retarget_shell(SH_BODY, ev, fix)
        self.assertEqual((n_out, n_fix), (1, 1))


class LeakScan7415(GuardedCase):
    def test_host_roots_are_in_the_prefix_set_7415(self):
        bb = load("build_bundle")
        for prefix in ("/Users/", "/Volumes/", "/var/folders/", "/root/"):
            with self.subTest(prefix=prefix):
                self.assertIn(prefix, bb.HOST_PATH_PREFIXES)
                pats = bb.leak_patterns(Path("/wt-x"), Path("/out-x"))
                self.assertTrue(bb.hits(f"saw {prefix}someone/file in the log", pats))

    def test_resolved_run_paths_are_scanned_7415(self):
        bb = load("build_bundle")
        rc = load("run_cert")
        pats = bb.leak_patterns(Path("/wt-x"), Path("/out-x"))
        for p in (str(rc.REPO_ROOT), str(Path.home()), str(rc.run_tmpdir())):
            with self.subTest(path=p):
                self.assertIn(p, pats)

    def test_tmp_dir_override_and_unresolved_forms_are_scanned_7415(self):
        bb = load("build_bundle")
        with mock.patch.dict(os.environ, {"CERT_TMPDIR": "/data/cert-tmp-x"}):
            pats = bb.leak_patterns(Path("/wt-x"), Path("/out-x"), unresolved=("/link/wt-x", "/link/out-x"))
        for p in ("/data/cert-tmp-x", "/link/wt-x", "/link/out-x"):
            with self.subTest(path=p):
                self.assertIn(p, pats)


class FedIds7423(ScratchCase):
    def test_git_grep_error_is_an_exit_3_not_zero_ids_7423(self):
        prep = load("prep")
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as cm:
            prep.fed_ids(self.dir / "not-a-repo", "HEAD")
        self.assertEqual(cm.exception.code, 3)

    def test_no_match_is_an_empty_set_7423(self):
        prep = load("prep")
        wt, _tip = make_repo(self.dir / "repo", {"src/a.rs": "fn main() {}\n"})
        self.assertEqual(prep.fed_ids(wt, "HEAD"), set())

    def test_match_is_returned_7423(self):
        prep = load("prep")
        wt, _tip = make_repo(self.dir / "repo", {"src/a.rs": 'const X: &str = "AI_MEMORY_FED_ONE";\n'})
        self.assertEqual(prep.fed_ids(wt, "HEAD"), {"AI_MEMORY_FED_ONE"})


class AloneHeader7425(ScratchCase):
    def make(self):
        rc = load("run_cert")
        return rc.Run(argparse.Namespace(tip=TIP, wt=str(self.dir), outd=str(self.dir / "o"), leg="chain",
                                         targets=str(self.dir / "t"), tmpdir=str(self.dir / "tmp")))

    def test_header_omits_ionice_when_it_is_not_installed_7425(self):
        r = self.make()
        with mock.patch("shutil.which", return_value=None):
            self.assertNotIn("ionice", r.priority_desc())
            self.assertNotIn("ionice", r.low_priority("1", "x.sh"))
        self.assertIn("nice 15", r.priority_desc())

    def test_header_states_ionice_when_it_is_used_7425(self):
        r = self.make()
        with mock.patch("shutil.which", return_value="/usr/bin/ionice"):
            self.assertIn("ionice -c3", r.priority_desc())
            self.assertIn("ionice", r.low_priority("1", "x.sh"))


class PrepText7417(GuardedCase):
    def test_docstring_names_the_python_expiry_gate_and_spacing_is_restored_7417(self):
        text = (EVIDENCE / "prep.py").read_text()
        self.assertNotIn("check-cert-expiry.sh", text)
        self.assertIn("scripts/check_cert_expiry.py", text.split('"""')[1])
        self.assertIn("FED_ID = re.compile(", text)


if __name__ == "__main__":
    unittest.main()
