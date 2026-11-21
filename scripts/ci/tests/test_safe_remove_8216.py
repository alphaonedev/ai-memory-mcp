# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Pin scripts/ci/safe_remove.py (#8216, PR 9812 round 1, security findings 1, 2, 6, 7, 10).

Defect class: the checked object is not the used object. Invariant, for all inputs: a directory is removed
only through the descriptor it was opened by (O_NOFOLLOW, one device, bounded depth), the tag is proven through
that same descriptor, the tag is removed last, a tree over a bound is refused before anything is unlinked, and
every refusal or failure carries its own exact reason. The swap tests change the object between the proof and
the removal with a patched step, never with a sleep.

All trees live under <clone>/.local-runs/ and the tests remove nothing outside it.

Run: python3.12 -I -m unittest discover -s scripts/ci/tests -p test_safe_remove_8216.py
Python 3.12+, standard library only.
"""

import errno
import importlib.util
import os
import shutil
import signal
import stat
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = REPO_ROOT / "scripts" / "ci" / "safe_remove.py"
LOCAL_RUNS = REPO_ROOT / ".local-runs"

SIGNATURE = b"Signature: 8a477f597d28d172789f06886806bc55"
TAG = "CACHEDIR.TAG"
BIG_TREE_FILES = 100_000
BIG_TREE_CEILING_SECS = 30.0
FIFO_ALARM_SECS = 10


def load_module():
    spec = importlib.util.spec_from_file_location("safe_remove_8216", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["safe_remove_8216"] = module
    spec.loader.exec_module(module)
    return module


sr = load_module()
TAG_SPEC = sr.TagSpec(TAG, SIGNATURE)


def force_remove(path: Path) -> None:
    """Test cleanup: restore owner bits (a test makes unreadable dirs), then remove; only under .local-runs."""
    assert str(path).startswith(str(LOCAL_RUNS)), path
    for root, dirs, _files in os.walk(path):
        for name in dirs:
            try:
                os.chmod(os.path.join(root, name), 0o700)
            except OSError:
                pass  # a path over PATH_MAX; the test cleans such a tree through the module itself
    shutil.rmtree(path, ignore_errors=True)


class Base(unittest.TestCase):
    def setUp(self):
        LOCAL_RUNS.mkdir(exist_ok=True)
        self.root = Path(tempfile.mkdtemp(prefix="safe-remove-8216-", dir=LOCAL_RUNS))
        self.addCleanup(force_remove, self.root)
        self.parent = self.root / "parent"
        self.parent.mkdir()
        self.parent_fd = os.open(self.parent, sr.DIR_OPEN_FLAGS)
        self.addCleanup(os.close, self.parent_fd)

    def target(self, name="target", signature=SIGNATURE) -> Path:
        path = self.parent / name
        path.mkdir()
        (path / TAG).write_bytes(signature + b"\n# cache\n")
        return path

    def victim(self) -> Path:
        path = self.root / "victim"
        path.mkdir()
        (path / "keep.txt").write_text("keep")
        return path

    def run_remove(self, name="target", **kwargs):
        kwargs.setdefault("tag", TAG_SPEC)
        return sr.check_and_remove(self.parent_fd, name, **kwargs)


class RemovesTheProvenObject(Base):
    def test_nested_tree_is_removed_and_counted(self):
        target = self.target()
        (target / "a.txt").write_text("a")
        (target / "sub" / "deep").mkdir(parents=True)
        (target / "sub" / "deep" / "b.txt").write_text("b")
        result = self.run_remove()
        # entries: a.txt, sub, sub/deep, b.txt, the tag = 5 (the top directory is not counted)
        self.assertEqual(result, sr.Result(sr.Status.REMOVED, "", 5))
        self.assertFalse(target.exists())

    def test_symlink_inside_is_unlinked_never_followed(self):
        target = self.target()
        outside = self.victim()
        (target / "link").symlink_to(outside)
        (target / "filelink").symlink_to(outside / "keep.txt")
        result = self.run_remove()
        self.assertEqual(result, sr.Result(sr.Status.REMOVED, "", 3))
        self.assertEqual((outside / "keep.txt").read_text(), "keep")

    def test_hard_link_is_unlinked_and_its_mode_and_content_stay(self):
        target = self.target()
        outside = self.victim()
        shared = outside / "keep.txt"
        shared.chmod(0o444)
        os.link(shared, target / "linked")
        result = self.run_remove()
        self.assertEqual(result.status, sr.Status.REMOVED)
        self.assertEqual(stat.S_IMODE(shared.stat().st_mode), 0o444)
        self.assertEqual(shared.read_text(), "keep")

    def test_read_only_and_unreadable_directories_are_fixed_through_their_descriptor(self):
        target = self.target()
        read_only = target / "ro"
        read_only.mkdir()
        (read_only / "f").write_text("x")
        read_only.chmod(0o500)
        sealed = target / "sealed"
        sealed.mkdir()
        (sealed / "g").write_text("y")
        sealed.chmod(0o000)
        result = self.run_remove()
        self.assertEqual(result, sr.Result(sr.Status.REMOVED, "", 5))
        self.assertFalse(target.exists())

    def test_no_subprocess_is_started(self):
        target = self.target()
        (target / "sub").mkdir()
        (target / "sub" / "f").write_text("x")
        (target / "sub").chmod(0o500)
        boom = AssertionError("a subprocess was started")
        with mock.patch("subprocess.Popen", side_effect=boom), mock.patch("subprocess.run", side_effect=boom):
            result = self.run_remove()
        self.assertEqual(result.status, sr.Status.REMOVED)

    def test_dry_run_removes_nothing_and_counts_what_would_go(self):
        target = self.target()
        (target / "a.txt").write_text("a")
        result = self.run_remove(dry_run=True)
        self.assertEqual(result, sr.Result(sr.Status.WOULD_REMOVE, "", 2))
        self.assertTrue((target / "a.txt").exists())
        self.assertTrue((target / TAG).exists())

    def test_tag_none_removes_without_a_tag(self):
        plain = self.parent / "plain"
        plain.mkdir()
        (plain / "f").write_text("x")
        result = self.run_remove("plain", tag=None)
        self.assertEqual(result, sr.Result(sr.Status.REMOVED, "", 1))
        self.assertFalse(plain.exists())

    def test_tag_with_more_lines_after_the_signature_is_proven(self):
        self.target()
        self.assertEqual(self.run_remove().status, sr.Status.REMOVED)

    def test_100k_entries_are_removed_inside_the_ceiling(self):
        target = self.target()
        for index in range(BIG_TREE_FILES):
            (target / f"f{index}").write_bytes(b"")
        started = time.monotonic()
        result = self.run_remove()
        elapsed = time.monotonic() - started
        self.assertEqual(result, sr.Result(sr.Status.REMOVED, "", 100_001))
        self.assertLess(elapsed, BIG_TREE_CEILING_SECS)


class RefusesTheWrongObject(Base):
    def test_missing_directory_is_absent(self):
        self.assertEqual(self.run_remove(), sr.Result(sr.Status.ABSENT, "directory does not exist", 0))

    def test_symlink_directory_is_refused_and_its_target_is_untouched(self):
        outside = self.victim()
        (outside / TAG).write_bytes(SIGNATURE + b"\n")
        (self.parent / "target").symlink_to(outside)
        result = self.run_remove()
        self.assertEqual(result, sr.Result(sr.Status.REFUSED, "directory is a symlink", 0))
        self.assertEqual((outside / "keep.txt").read_text(), "keep")
        self.assertTrue((outside / TAG).exists())

    def test_regular_file_is_refused(self):
        (self.parent / "target").write_text("file")
        self.assertEqual(self.run_remove(), sr.Result(sr.Status.REFUSED, "path is not a directory", 0))

    def test_name_that_is_not_one_component_is_refused(self):
        for name in ("", ".", "..", "a/b", "../x", "a\0b"):
            with self.subTest(name=name):
                self.assertEqual(
                    self.run_remove(name),
                    sr.Result(sr.Status.REFUSED, "name is not a single path component", 0),
                )

    def test_other_device_is_refused_with_the_label(self):
        target = self.target()
        wrong = os.fstat(self.parent_fd).st_dev + 1
        result = self.run_remove(expected_dev=wrong, device_label="the work root")
        self.assertEqual(result, sr.Result(sr.Status.REFUSED, "directory is on another device than the work root", 0))
        self.assertTrue((target / TAG).exists())

    def test_default_device_label_names_the_parent(self):
        self.target()
        result = self.run_remove(expected_dev=os.fstat(self.parent_fd).st_dev + 1)
        self.assertEqual(result.reason, "directory is on another device than its parent")

    def test_open_failure_has_its_own_reason(self):
        self.target()
        real_open = os.open

        def failing(path, flags, *args, **kwargs):
            if path == "target":
                raise OSError(errno.EMFILE, "Too many open files")
            return real_open(path, flags, *args, **kwargs)

        with mock.patch.object(sr.os, "open", side_effect=failing):
            result = self.run_remove()
        self.assertEqual(result, sr.Result(sr.Status.REFUSED, "directory cannot be opened: Too many open files", 0))

    def test_examine_failure_has_its_own_reason(self):
        self.target()
        real_open, real_stat = os.open, os.stat

        def failing_open(path, flags, *args, **kwargs):
            if path == "target":
                raise OSError(errno.EACCES, "Permission denied")
            return real_open(path, flags, *args, **kwargs)

        def failing_stat(path, *args, **kwargs):
            if path == "target":
                raise OSError(errno.EACCES, "Permission denied")
            return real_stat(path, *args, **kwargs)

        with mock.patch.object(sr.os, "open", side_effect=failing_open), mock.patch.object(
            sr.os, "stat", side_effect=failing_stat
        ):
            result = self.run_remove()
        self.assertEqual(result, sr.Result(sr.Status.REFUSED, "directory cannot be examined: Permission denied", 0))


class TagStates(Base):
    """Every tag state has its own exact reason and nothing is removed."""

    def assert_refused(self, target: Path, reason: str):
        result = self.run_remove()
        self.assertEqual(result, sr.Result(sr.Status.REFUSED, reason, 0))
        self.assertTrue(target.exists())
        self.assertTrue((target / "keep").exists())

    def bare(self) -> Path:
        path = self.parent / "target"
        path.mkdir()
        (path / "keep").write_text("keep")
        return path

    def test_missing_tag(self):
        self.assert_refused(self.bare(), "CACHEDIR.TAG is missing")

    def test_symlink_tag(self):
        target = self.bare()
        outside = self.root / "real-tag"
        outside.write_bytes(SIGNATURE + b"\n")
        (target / TAG).symlink_to(outside)
        self.assert_refused(target, "CACHEDIR.TAG is a symlink")

    def test_directory_tag(self):
        target = self.bare()
        (target / TAG).mkdir()
        self.assert_refused(target, "CACHEDIR.TAG is a directory")

    def test_fifo_tag_returns_at_once(self):
        target = self.bare()
        os.mkfifo(target / TAG)

        def too_slow(_signum, _frame):
            raise AssertionError("the FIFO tag blocked")

        previous = signal.signal(signal.SIGALRM, too_slow)
        signal.alarm(FIFO_ALARM_SECS)
        try:
            self.assert_refused(target, "CACHEDIR.TAG is not a regular file (fifo)")
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, previous)

    def test_wrong_signature(self):
        target = self.bare()
        (target / TAG).write_bytes(b"Signature: 00000000000000000000000000000000\n")
        self.assert_refused(target, "CACHEDIR.TAG first line is not the expected signature")

    def test_signature_with_a_suffix_or_carriage_return_is_wrong(self):
        for first in (SIGNATURE + b" ", SIGNATURE + b"\r", b" " + SIGNATURE, SIGNATURE[:-1], b""):
            with self.subTest(first=first):
                target = self.parent / "target"
                if target.exists():
                    force_remove(target)
                target = self.bare()
                (target / TAG).write_bytes(first + b"\n" + SIGNATURE + b"\n")
                self.assert_refused(target, "CACHEDIR.TAG first line is not the expected signature")

    def test_signature_only_on_the_second_line_is_wrong(self):
        target = self.bare()
        (target / TAG).write_bytes(b"hello\n" + SIGNATURE + b"\n")
        self.assert_refused(target, "CACHEDIR.TAG first line is not the expected signature")

    def test_empty_tag(self):
        target = self.bare()
        (target / TAG).write_bytes(b"")
        self.assert_refused(target, "CACHEDIR.TAG first line is not the expected signature")

    def test_unreadable_tag(self):
        target = self.bare()
        (target / TAG).write_bytes(SIGNATURE + b"\n")
        (target / TAG).chmod(0o000)
        self.assert_refused(target, "CACHEDIR.TAG cannot be read: Permission denied")

    def test_examine_failure(self):
        target = self.bare()
        real_stat = os.stat

        def failing(path, *args, **kwargs):
            if path == TAG:
                raise OSError(errno.EIO, "Input/output error")
            return real_stat(path, *args, **kwargs)

        with mock.patch.object(sr.os, "stat", side_effect=failing):
            result = self.run_remove()
        self.assertEqual(result, sr.Result(sr.Status.REFUSED, "CACHEDIR.TAG cannot be examined: Input/output error", 0))
        self.assertTrue((target / "keep").exists())

    def test_read_failure(self):
        target = self.target()
        with mock.patch.object(sr.os, "read", side_effect=OSError(errno.EIO, "Input/output error")):
            result = self.run_remove()
        self.assertEqual(result, sr.Result(sr.Status.REFUSED, "CACHEDIR.TAG cannot be read: Input/output error", 0))
        self.assertTrue((target / TAG).exists())

    def test_kind_reasons_for_every_non_regular_mode(self):
        table = (
            (stat.S_IFLNK, "CACHEDIR.TAG is a symlink"),
            (stat.S_IFDIR, "CACHEDIR.TAG is a directory"),
            (stat.S_IFIFO, "CACHEDIR.TAG is not a regular file (fifo)"),
            (stat.S_IFSOCK, "CACHEDIR.TAG is not a regular file (socket)"),
            (stat.S_IFBLK, "CACHEDIR.TAG is not a regular file (block device)"),
            (stat.S_IFCHR, "CACHEDIR.TAG is not a regular file (character device)"),
        )
        for mode, reason in table:
            with self.subTest(reason=reason):
                self.assertEqual(sr._tag_kind_reason(TAG_SPEC, mode | 0o644), reason)
        self.assertEqual(sr._tag_kind_reason(TAG_SPEC, 0o644), "CACHEDIR.TAG is not a regular file (other)")

    def swap_tag_after_stat(self, target: Path, make_replacement):
        """The stat says regular file; the object is swapped before the open (no sleep)."""
        real_stat = os.stat
        regular = self.root / "regular"
        regular.write_bytes(SIGNATURE + b"\n")

        def swapping(path, *args, **kwargs):
            if path == TAG and kwargs.get("dir_fd") is not None:
                result = real_stat(regular)
                os.unlink(TAG, dir_fd=kwargs["dir_fd"])
                make_replacement(target / TAG)
                return result
            return real_stat(path, *args, **kwargs)

        with mock.patch.object(sr.os, "stat", side_effect=swapping):
            return self.run_remove()

    def test_tag_swapped_to_a_symlink_between_stat_and_open_is_refused(self):
        target = self.target()
        outside = self.root / "outside-tag"
        outside.write_bytes(SIGNATURE + b"\n")
        result = self.swap_tag_after_stat(target, lambda path: path.symlink_to(outside))
        self.assertEqual(result, sr.Result(sr.Status.REFUSED, "CACHEDIR.TAG is a symlink", 0))
        self.assertTrue(outside.exists())

    def test_tag_swapped_to_a_fifo_between_stat_and_open_is_refused_at_once(self):
        target = self.target()
        result = self.swap_tag_after_stat(target, lambda path: os.mkfifo(path))
        self.assertEqual(result, sr.Result(sr.Status.REFUSED, "CACHEDIR.TAG is not a regular file (fifo)", 0))


class SwapBetweenProofAndRemoval(Base):
    """The object that was proven is the object that is removed; a replaced name is left alone."""

    def swap_after_proof(self, replace):
        real_prove = sr._prove_tag

        def prove_then_swap(dir_fd, tag):
            reason = real_prove(dir_fd, tag)
            replace()
            return reason

        with mock.patch.object(sr, "_prove_tag", side_effect=prove_then_swap):
            return self.run_remove()

    def test_symlink_swapped_in_after_the_proof_leaves_the_victim_alone(self):
        target = self.target()
        (target / "a.txt").write_text("a")
        outside = self.victim()

        def replace():
            target.rename(self.parent / "moved")
            (self.parent / "target").symlink_to(outside)

        result = self.swap_after_proof(replace)
        self.assertEqual(result, sr.Result(sr.Status.PARTIAL, sr.REASON_REPLACED, 2))
        self.assertEqual((outside / "keep.txt").read_text(), "keep")
        self.assertTrue((self.parent / "target").is_symlink())
        self.assertEqual(list((self.parent / "moved").iterdir()), [])  # the proven object was emptied

    def test_another_directory_swapped_in_after_the_proof_is_left_alone(self):
        target = self.target()
        decoy = self.root / "decoy"
        decoy.mkdir()
        (decoy / "precious").write_text("precious")

        def replace():
            target.rename(self.parent / "moved")
            decoy.rename(self.parent / "target")

        result = self.swap_after_proof(replace)
        self.assertEqual(result, sr.Result(sr.Status.PARTIAL, sr.REASON_REPLACED, 1))
        self.assertEqual((self.parent / "target" / "precious").read_text(), "precious")

    def test_name_removed_after_the_proof_counts_as_removed(self):
        target = self.target()

        def replace():
            target.rename(self.parent / "moved")

        result = self.swap_after_proof(replace)
        self.assertEqual(result, sr.Result(sr.Status.REMOVED, "", 1))


class PartWayAndBounds(Base):
    def fail_rmdir_of(self, name):
        real = os.rmdir

        def failing(path, *args, **kwargs):
            if path == name and kwargs.get("dir_fd") is not None:
                raise OSError(errno.EACCES, "Permission denied")
            return real(path, *args, **kwargs)

        return mock.patch.object(sr.os, "rmdir", side_effect=failing)

    def test_failure_part_way_is_partial_and_the_tag_stays_so_the_next_run_clears_it(self):
        target = self.target()
        (target / "a.txt").write_text("a")
        (target / "sub").mkdir()
        (target / "sub" / "f").write_text("f")
        with self.fail_rmdir_of("sub"):
            first = self.run_remove()
        self.assertEqual(first, sr.Result(sr.Status.PARTIAL, "remove failed: Permission denied", 2))
        self.assertTrue((target / TAG).exists(), "the tag is removed last")
        second = self.run_remove()
        self.assertEqual(second, sr.Result(sr.Status.REMOVED, "", 2))
        self.assertFalse(target.exists())

    def test_failure_before_anything_is_removed_is_refused_not_partial(self):
        target = self.target()
        (target / "a.txt").write_text("a")
        with mock.patch.object(sr.os, "unlink", side_effect=OSError(errno.EPERM, "Operation not permitted")):
            result = self.run_remove()
        self.assertEqual(result, sr.Result(sr.Status.REFUSED, "remove failed: Operation not permitted", 0))
        self.assertTrue((target / TAG).exists())

    def test_tag_unlink_failure_is_partial_with_every_other_entry_gone(self):
        target = self.target()
        (target / "a.txt").write_text("a")
        real = os.unlink

        def failing(path, *args, **kwargs):
            if path == TAG:
                raise OSError(errno.EPERM, "Operation not permitted")
            return real(path, *args, **kwargs)

        with mock.patch.object(sr.os, "unlink", side_effect=failing):
            result = self.run_remove()
        self.assertEqual(result, sr.Result(sr.Status.PARTIAL, "remove failed: Operation not permitted", 1))
        self.assertEqual(sorted(p.name for p in target.iterdir()), [TAG])

    def chain(self, target: Path, depth: int):
        fd = os.open(target, sr.DIR_OPEN_FLAGS)
        try:
            for index in range(depth):
                os.mkdir(f"d{index}", dir_fd=fd)
                child = os.open(f"d{index}", sr.DIR_OPEN_FLAGS, dir_fd=fd)
                os.close(fd)
                fd = child
        finally:
            os.close(fd)

    def test_depth_at_the_cap_is_removed_and_one_over_is_refused_before_any_unlink(self):
        target = self.target()
        (target / "top.txt").write_text("top")
        self.chain(target, 5)
        refused = self.run_remove(max_depth=4)
        self.assertEqual(refused, sr.Result(sr.Status.REFUSED, "tree deeper than 4 levels, nothing removed", 0))
        self.assertTrue((target / "top.txt").exists(), "nothing is unlinked before the refusal")
        self.assertTrue((target / TAG).exists())
        allowed = self.run_remove(max_depth=5)
        self.assertEqual(allowed.status, sr.Status.REMOVED)

    def test_default_depth_cap_is_256(self):
        self.assertEqual(sr.MAX_TREE_DEPTH, 256)
        target = self.target()
        self.chain(target, 258)
        # a path this long cannot be walked by name: clear it through the module with a larger cap
        self.addCleanup(lambda: self.run_remove(tag=None, max_depth=10_000))
        result = self.run_remove()
        self.assertEqual(result, sr.Result(sr.Status.REFUSED, "tree deeper than 256 levels, nothing removed", 0))
        self.assertTrue((target / TAG).exists())

    def test_entry_cap_exactly_at_is_removed_and_one_over_is_refused(self):
        target = self.target()
        (target / "a").write_text("a")
        (target / "b").write_text("b")
        refused = self.run_remove(max_entries=2)
        self.assertEqual(refused, sr.Result(sr.Status.REFUSED, "more than 2 entries, nothing removed", 0))
        self.assertTrue((target / "a").exists())
        allowed = self.run_remove(max_entries=3)
        self.assertEqual(allowed, sr.Result(sr.Status.REMOVED, "", 3))

    def test_default_entry_cap_is_5_million(self):
        self.assertEqual(sr.MAX_REMOVE_ENTRIES, 5_000_000)

    def test_directory_entries_count_towards_the_cap(self):
        target = self.target()
        for name in ("d1", "d2", "d3"):
            (target / name).mkdir()
        refused = self.run_remove(max_entries=3)
        self.assertEqual(refused.reason, "more than 3 entries, nothing removed")

    def fake_device_for(self, directory: Path):
        real = os.fstat
        ino = directory.stat().st_ino

        def fake(fd):
            info = real(fd)
            if info.st_ino == ino:
                return types.SimpleNamespace(st_dev=info.st_dev + 1, st_mode=info.st_mode, st_ino=info.st_ino)
            return info

        return mock.patch.object(sr.os, "fstat", side_effect=fake)

    def test_a_directory_on_another_device_inside_is_refused_before_any_unlink(self):
        target = self.target()
        (target / "top.txt").write_text("top")
        (target / "mount").mkdir()
        with self.fake_device_for(target / "mount"):
            result = self.run_remove()
        self.assertEqual(result, sr.Result(sr.Status.REFUSED, "a directory inside is on another device, nothing removed", 0))
        self.assertTrue((target / "top.txt").exists())

    def test_removal_pass_refuses_a_device_boundary_that_appears_after_the_first_pass(self):
        target = self.target()
        (target / "mount").mkdir()
        (target / "mount" / "f").write_text("f")
        with mock.patch.object(sr, "_first_pass"), self.fake_device_for(target / "mount"):
            result = self.run_remove()
        self.assertEqual(result, sr.Result(sr.Status.REFUSED, "remove failed: crosses a device boundary", 0))
        self.assertTrue((target / "mount" / "f").exists())

    def test_removal_pass_refuses_depth_that_appears_after_the_first_pass(self):
        target = self.target()
        self.chain(target, 3)
        with mock.patch.object(sr, "_first_pass"):
            result = self.run_remove(max_depth=1)
        self.assertEqual(result, sr.Result(sr.Status.REFUSED, "remove failed: tree deeper than 1 levels", 0))

    def test_unreadable_tree_in_the_first_pass_is_refused_with_its_cause(self):
        target = self.target()
        with mock.patch.object(sr, "_list", side_effect=PermissionError(errno.EACCES, "Permission denied")):
            result = self.run_remove()
        self.assertEqual(
            result, sr.Result(sr.Status.REFUSED, "tree cannot be read: Permission denied, nothing removed", 0)
        )
        self.assertTrue((target / TAG).exists())

    def test_iter_names_lists_sorted_names(self):
        target = self.target()
        (target / "b").write_text("b")
        (target / "a").write_text("a")
        fd = os.open(target, sr.DIR_OPEN_FLAGS)
        try:
            self.assertEqual(list(sr.iter_names(fd)), ["CACHEDIR.TAG", "a", "b"])
        finally:
            os.close(fd)


class OpenDirectory(Base):
    def test_returns_a_usable_descriptor(self):
        self.target()
        fd = sr.open_directory(self.parent_fd, "target")
        try:
            self.assertTrue(stat.S_ISDIR(os.fstat(fd).st_mode))
        finally:
            os.close(fd)

    def test_not_proven_carries_the_absent_flag_only_for_a_missing_name(self):
        with self.assertRaises(sr.NotProven) as missing:
            sr.open_directory(self.parent_fd, "nope")
        self.assertEqual((missing.exception.reason, missing.exception.absent), ("directory does not exist", True))
        (self.parent / "file").write_text("x")
        with self.assertRaises(sr.NotProven) as other:
            sr.open_directory(self.parent_fd, "file")
        self.assertEqual((other.exception.reason, other.exception.absent), ("path is not a directory", False))

    def test_descriptor_is_not_leaked_on_a_device_refusal(self):
        self.target()
        before = len(os.listdir("/dev/fd"))
        with self.assertRaises(sr.NotProven):
            sr.open_directory(self.parent_fd, "target", expected_dev=os.fstat(self.parent_fd).st_dev + 1)
        self.assertEqual(len(os.listdir("/dev/fd")), before)


if __name__ == "__main__":
    unittest.main()
