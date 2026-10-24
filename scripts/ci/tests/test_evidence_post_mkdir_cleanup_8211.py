#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""#8211: a failure after the private-directory mkdir leaves no empty directory in the scratch root, and a
symlink planted at the path is never followed or removed (run_cert.Run.private_directory, build_bundle.publish_bundle)."""
import errno
import os
import unittest
import unittest.mock as mock

from test_evidence_generator_5040_5042 import ScratchCase, load

FILES = {"proof.txt": b"approved\n"}


class PostMkdirCleanup8211(ScratchCase):
    def setUp(self):
        super().setUp()
        self.root = self.dir / "scratch-root"
        self.root.mkdir(mode=0o755)
        self.outside = self.dir / "outside"
        self.outside.mkdir()
        (self.outside / "keep.txt").write_text("keep\n")

    def assert_outside_untouched(self):
        self.assertEqual([p.name for p in self.outside.iterdir()], ["keep.txt"])

    def swap_for_symlink(self, name, dir_fd):
        os.rmdir(name, dir_fd=dir_fd)
        os.symlink(str(self.outside), name, dir_fd=dir_fd)

    def run_cert_failure(self, plant):
        run_cert = load("run_cert")
        scratch_fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, scratch_fd)

        def failing(name, *, dir_fd=None):
            if plant:
                self.swap_for_symlink(name, dir_fd)
            raise OSError(errno.EMFILE, "injected descriptor exhaustion")

        with mock.patch.object(run_cert, "open_scratch", side_effect=failing):
            with self.assertRaises((OSError, run_cert.ConfigError)):
                run_cert.Run.private_directory(scratch_fd, "child-")

    def test_run_cert_removes_the_empty_directory_after_a_post_mkdir_failure_8211(self):
        self.run_cert_failure(plant=False)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_run_cert_leaves_a_planted_symlink_untouched_8211(self):
        self.run_cert_failure(plant=True)
        entries = list(self.root.iterdir())
        self.assertEqual(len(entries), 1)
        self.assertTrue(entries[0].is_symlink())
        self.assert_outside_untouched()

    def publish_failure(self, prefix, plant):
        bb = load("build_bundle")
        checkout = self.dir / "checkout"
        checkout.mkdir()
        (checkout / bb.SCRATCH_DIR).mkdir(mode=0o755)
        wanted = bb.PRIVATE_PREFIX if prefix == "private" else bb.STAGE_NAME
        real_open = os.open
        fired = []

        def failing(path, flags, mode=0o777, *, dir_fd=None):
            if not fired and dir_fd is not None and str(path).startswith(wanted):
                fired.append(path)
                if plant:
                    self.swap_for_symlink(str(path), dir_fd)
                raise OSError(errno.EMFILE, "injected descriptor exhaustion")
            return real_open(path, flags, mode, dir_fd=dir_fd)

        with mock.patch.object(os, "open", side_effect=failing):
            with self.assertRaises(bb.Fatal):
                bb.publish_bundle(checkout, checkout / "published", FILES, bb.manifest_text(FILES))
        self.assertTrue(fired, "fault was not injected")
        return checkout / bb.SCRATCH_DIR

    def test_build_bundle_removes_the_private_directory_after_a_post_mkdir_failure_8211(self):
        scratch = self.publish_failure("private", plant=False)
        self.assertEqual(list(scratch.iterdir()), [])

    def test_build_bundle_leaves_a_planted_private_symlink_untouched_8211(self):
        scratch = self.publish_failure("private", plant=True)
        entries = list(scratch.iterdir())
        self.assertEqual(len(entries), 1)
        self.assertTrue(entries[0].is_symlink())
        self.assert_outside_untouched()

    def test_build_bundle_removes_the_stage_and_private_directories_after_a_post_mkdir_failure_8211(self):
        scratch = self.publish_failure("stage", plant=False)
        self.assertEqual(list(scratch.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
