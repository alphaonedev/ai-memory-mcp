#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for scripts/ci/clean_job_tmpdir.py (#7748).

The helper purges the top-level entries of a runner TMPDIR that the node
operator opted in with a marker file, and refuses everything else. Fixtures
live under <repo>/.local-runs/7748-<pid>/, never a tmp path.

Run: python3 -m unittest discover -s scripts/ci/tests -p "test_clean_job_tmpdir_7748.py" -t scripts/ci/tests
Python 3.9+, standard library only.
"""
import io
import os
import shutil
import sys
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "scripts" / "ci"))
import clean_job_tmpdir as cjt  # noqa: E402

MARKER = ".ai-memory-ci-purgeable"
HOME = "/Users/fixture-home"


def run_main(argv, environ):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        try:
            rc = cjt.main(argv, environ)
        except SystemExit as exc:
            rc = exc.code
    return rc, out.getvalue(), err.getvalue()


class Base(unittest.TestCase):
    def setUp(self):
        self.base = REPO / ".local-runs" / ("7748-%d" % os.getpid())
        self.root = self.base / self.id().split(".")[-1]
        shutil.rmtree(str(self.root), ignore_errors=True)
        self.tmp = self.root / "runner" / "_tmp"
        self.tmp.mkdir(parents=True)
        self.outside = self.root / "outside"
        self.outside.mkdir()
        (self.outside / "keep.txt").write_text("keep", encoding="utf-8")

    def tearDown(self):
        for dirpath, dirnames, _ in os.walk(str(self.root)):
            for name in dirnames:
                full = os.path.join(dirpath, name)
                if not os.path.islink(full):
                    os.chmod(full, 0o755)
        shutil.rmtree(str(self.root), ignore_errors=True)
        try:
            self.base.rmdir()
        except OSError:
            pass

    def mark(self):
        (self.tmp / MARKER).write_text("", encoding="utf-8")

    def populate(self):
        (self.tmp / "a.db").write_text("x" * 10, encoding="utf-8")
        (self.tmp / "a.db-wal").write_text("y", encoding="utf-8")
        sub = self.tmp / "ef-posture-audit-1"
        (sub / "deep").mkdir(parents=True)
        (sub / "deep" / "f").write_text("z" * 5, encoding="utf-8")
        os.symlink(str(self.outside / "keep.txt"), str(self.tmp / "link-file"))
        os.symlink(str(self.outside), str(self.tmp / "link-dir"))
        os.symlink(str(self.outside), str(sub / "inner-link"))

    def names(self):
        return sorted(p.name for p in self.tmp.iterdir())


class Refusals(Base):
    def test_unset_tmpdir_is_a_noop_notice_7748(self):
        for env in ({}, {"TMPDIR": ""}):
            rc, out, _ = run_main(["--apply"], env)
            self.assertEqual(rc, 0)
            self.assertEqual(out.count("::notice::"), 1, out)

    def test_unmarked_dir_is_untouched_7748(self):
        self.populate()
        before = self.names()
        rc, out, _ = run_main(["--apply", "--tmpdir", str(self.tmp)], {})
        self.assertEqual(rc, 0)
        self.assertIn("::notice::", out)
        self.assertEqual(self.names(), before)

    def test_each_refused_path_class_7748(self):
        cases = ["/", "/tmp", "/private/tmp", "/var/tmp", "/var/folders", "/var/folders/ab/cd/T",
                 HOME, "/Users", "/Users/Shared", "/a/b"]
        for case in cases:
            self.assertIsNotNone(cjt.refusal_reason(case, HOME, marker=None), case)
        self.assertIsNone(cjt.refusal_reason("/Users/Shared/actions-runner/_tmp", HOME, marker=None))

    def test_forbidden_list_is_a_parameter_7748(self):
        sysdir = self.root / "sysdir"
        sysdir.mkdir()
        (sysdir / MARKER).write_text("", encoding="utf-8")
        self.assertIsNone(cjt.refusal_reason(str(sysdir), HOME, forbidden=[]))
        self.assertIn("forbidden", cjt.refusal_reason(str(sysdir), HOME, forbidden=[str(sysdir)]))
        self.assertIn("forbidden", cjt.refusal_reason(str(sysdir / "x"), HOME, forbidden=[str(sysdir)]))

    def test_home_and_ancestors_refused_7748(self):
        for case in ("/Users/fixture-home", "/Users", "/"):
            self.assertIsNotNone(cjt.refusal_reason(case, HOME, forbidden=[], marker=None), case)
        self.assertIn("home", cjt.refusal_reason("/Users/fixture-home", HOME, forbidden=[], marker=None))

    def test_symlinked_tmpdir_refused_7748(self):
        self.mark()
        self.populate()
        link = self.root / "runner" / "_link"
        os.symlink(str(self.tmp), str(link))
        before = self.names()
        rc, out, _ = run_main(["--apply", "--tmpdir", str(link)], {})
        self.assertEqual(rc, 0)
        self.assertIn("symlink", out)
        self.assertEqual(self.names(), before)

    def test_bad_arguments_exit_2_7748(self):
        rc, _, _ = run_main(["--older-than-minutes", "nope", "--tmpdir", str(self.tmp)], {})
        self.assertEqual(rc, 2)
        rc, _, _ = run_main(["--older-than-minutes", "-1", "--tmpdir", str(self.tmp)], {})
        self.assertEqual(rc, 2)


class Purge(Base):
    def test_dry_run_removes_nothing_and_lists_7748(self):
        self.mark()
        self.populate()
        before = self.names()
        rc, out, _ = run_main(["--tmpdir", str(self.tmp)], {})
        self.assertEqual(rc, 0)
        self.assertEqual(self.names(), before)
        self.assertIn("a.db", out)
        self.assertIn("dry-run", out)

    def test_apply_removes_files_dirs_and_symlinks_7748(self):
        self.mark()
        self.populate()
        rc, out, _ = run_main(["--apply", "--tmpdir", str(self.tmp)], {})
        self.assertEqual(rc, 0)
        self.assertEqual(self.names(), [MARKER])
        self.assertTrue(self.tmp.is_dir())
        self.assertEqual((self.outside / "keep.txt").read_text(encoding="utf-8"), "keep")
        self.assertTrue((self.outside).is_dir())
        self.assertIn("removed=5", out)
        self.assertIn("failed=0", out)
        self.assertIn("bytes=16", out)

    def test_tmpdir_from_environment_7748(self):
        self.mark()
        self.populate()
        rc, _, _ = run_main(["--apply"], {"TMPDIR": str(self.tmp)})
        self.assertEqual(rc, 0)
        self.assertEqual(self.names(), [MARKER])

    def test_older_than_keeps_young_entries_7748(self):
        self.mark()
        old = self.tmp / "old.db"
        young = self.tmp / "young.db"
        old.write_text("o", encoding="utf-8")
        young.write_text("y", encoding="utf-8")
        stamp = time.time() - 3 * 3600
        os.utime(str(old), (stamp, stamp))
        rc, out, _ = run_main(["--apply", "--older-than-minutes", "60", "--tmpdir", str(self.tmp)], {})
        self.assertEqual(rc, 0)
        self.assertEqual(self.names(), [MARKER, "young.db"])
        self.assertIn("skipped=1", out)

    def test_removal_failure_counted_and_exit_zero_7748(self):
        if os.geteuid() == 0:
            self.skipTest("root ignores directory modes")
        self.mark()
        locked = self.tmp / "locked"
        (locked / "inner").mkdir(parents=True)
        (locked / "inner" / "f").write_text("x", encoding="utf-8")
        (self.tmp / "ok.db").write_text("x", encoding="utf-8")
        os.chmod(str(locked / "inner"), 0o500)
        rc, out, _ = run_main(["--apply", "--tmpdir", str(self.tmp)], {})
        self.assertEqual(rc, 0)
        self.assertNotIn("failed=0", out)
        self.assertIn("failed=", out)
        self.assertTrue((self.tmp / MARKER).exists())
        self.assertFalse((self.tmp / "ok.db").exists())
        self.assertTrue(self.tmp.is_dir())

    def test_marker_is_never_removed_even_when_old_7748(self):
        self.mark()
        stamp = time.time() - 30 * 86400
        os.utime(str(self.tmp / MARKER), (stamp, stamp))
        rc, _, _ = run_main(["--apply", "--tmpdir", str(self.tmp)], {})
        self.assertEqual(rc, 0)
        self.assertEqual(self.names(), [MARKER])

    def test_custom_marker_name_7748(self):
        (self.tmp / "other-marker").write_text("", encoding="utf-8")
        (self.tmp / "x").write_text("", encoding="utf-8")
        rc, _, _ = run_main(["--apply", "--marker", "other-marker", "--tmpdir", str(self.tmp)], {})
        self.assertEqual(rc, 0)
        self.assertEqual(self.names(), ["other-marker"])


if __name__ == "__main__":
    unittest.main()
