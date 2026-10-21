#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""LOW7870: guarded_scratch never leaks the descriptor it opened when post-open validation raises."""
import argparse
import errno
import os
import unittest
from unittest import mock

from test_evidence_generator_5040_5042 import ScratchCase, load

TIP = "a" * 40
PRIVATE_MODE = 0o700


class GuardedScratchDescriptor7870(ScratchCase):
    def setUp(self):
        super().setUp()
        self.rc = load("run_cert")
        self.tmpdir = self.dir / "scratch"
        self.targets = self.dir / "targets"
        self.tmpdir.mkdir(mode=PRIVATE_MODE)
        self.targets.mkdir(mode=PRIVATE_MODE)
        self.runner = self.rc.Run(argparse.Namespace(
            tip=TIP, wt=str(self.dir), outd=str(self.dir / "out"), leg="battery",
            tmpdir=str(self.tmpdir), targets=str(self.targets)))

    def guarded(self, fault):
        """Call guarded_scratch with `fault` raised by the validation fstat of the descriptor open_scratch returned.
        Returns (exception or None, descriptor)."""
        real_open_scratch, real_fstat = self.rc.open_scratch, os.fstat
        held = []

        def recording_open_scratch(path, **kw):
            fd = real_open_scratch(path, **kw)
            held.append(fd)
            return fd

        def faulty_fstat(fd):
            if held and fd == held[0] and fault is not None:
                raise fault
            return real_fstat(fd)

        raised = None
        with mock.patch.object(self.rc, "open_scratch", side_effect=recording_open_scratch), \
                mock.patch.object(os, "fstat", side_effect=faulty_fstat):
            try:
                result = self.runner.guarded_scratch(self.tmpdir)
            except BaseException as error:  # the test inspects every failure class
                raised = error
            else:
                held.append(result)
        return raised, held[0]

    @staticmethod
    def is_open(fd):
        try:
            os.fstat(fd)
        except OSError:
            return False
        return True

    def test_validation_oserror_closes_the_descriptor_7870(self):
        raised, fd = self.guarded(OSError(errno.EIO, "injected validation fstat error"))
        leaked = self.is_open(fd)
        if leaked:
            os.close(fd)
        self.assertIsInstance(raised, OSError)
        self.assertFalse(leaked, "guarded_scratch leaked its descriptor")

    def test_validation_interrupt_closes_the_descriptor_7870(self):
        raised, fd = self.guarded(KeyboardInterrupt())
        leaked = self.is_open(fd)
        if leaked:
            os.close(fd)
        self.assertIsInstance(raised, KeyboardInterrupt)
        self.assertFalse(leaked, "guarded_scratch leaked its descriptor")

    def test_success_transfers_an_open_descriptor_7870(self):
        raised, fd = self.guarded(None)
        try:
            self.assertIsNone(raised)
            self.assertTrue(self.is_open(fd))
        finally:
            if self.is_open(fd):
                os.close(fd)

    def test_replaced_root_still_closes_and_raises_config_error_7870(self):
        self.runner.scratch_identities[self.tmpdir] = (0, 0)
        raised, fd = self.guarded(None)
        leaked = self.is_open(fd)
        if leaked:
            os.close(fd)
        self.assertIsInstance(raised, self.rc.ConfigError)
        self.assertFalse(leaked)


if __name__ == "__main__":
    unittest.main()
