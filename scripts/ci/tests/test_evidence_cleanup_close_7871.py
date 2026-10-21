#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""LOW7871: a failing cleanup step never leaves a held directory descriptor open in publish_bundle."""
import errno
import os
import unittest
from pathlib import Path
from unittest import mock

from test_evidence_generator_5040_5042 import ScratchCase, load

FILES = {"proof.txt": b"approved\n"}
PUBLISHED = "published"


def descriptor_target(fd):
    try:
        return Path(os.readlink(f"/proc/self/fd/{fd}"))
    except OSError:
        return None


class CleanupClose7871(ScratchCase):
    def run_publish(self, name, victim):
        """Portable publication where the first close of the descriptor for `victim(checkout)` closes, then raises.
        Returns (fault injected, leaked descriptors)."""
        bundle = load("build_bundle")
        checkout = self.dir / name
        checkout.mkdir()
        target = victim(checkout.resolve())
        opened = []
        injected = []
        real_open, real_close = os.open, os.close

        def recording_open(*args, **kw):
            fd = real_open(*args, **kw)
            opened.append(fd)
            return fd

        def closing(fd):
            here = descriptor_target(fd)
            real_close(fd)
            if target is not None and here == target and not injected:
                injected.append(fd)
                raise OSError(errno.EIO, "injected close failure")

        with mock.patch.object(bundle, "rename_noreplace_native", None), \
                mock.patch.object(os, "open", side_effect=recording_open), \
                mock.patch.object(os, "close", side_effect=closing):
            try:
                bundle.publish_bundle(checkout, checkout / PUBLISHED, FILES, bundle.manifest_text(FILES))
            except OSError:
                pass
        leaked = []
        for fd in set(opened):
            try:
                os.fstat(fd)
            except OSError:
                continue
            leaked.append(fd)
            real_close(fd)
        return bool(injected), leaked

    def test_claim_close_failure_does_not_skip_held_descriptors_7871(self):
        injected, leaked = self.run_publish("claim", lambda checkout: checkout / PUBLISHED)
        self.assertTrue(injected, "fault was not injected")
        self.assertEqual(leaked, [])

    def test_one_descriptor_close_failure_does_not_skip_the_rest_7871(self):
        injected, leaked = self.run_publish("first", lambda checkout: checkout)
        self.assertTrue(injected, "fault was not injected")
        self.assertEqual(leaked, [])

    def test_clean_run_closes_everything_7871(self):
        injected, leaked = self.run_publish("clean", lambda checkout: None)
        self.assertFalse(injected)
        self.assertEqual(leaked, [])


if __name__ == "__main__":
    unittest.main()
