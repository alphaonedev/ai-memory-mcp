#!/usr/bin/env python3
"""#7876: run_cert closes every held descriptor even when an earlier close fails.

The first OSError is kept and re-raised after the loop, mirroring the #7871 pattern in build_bundle.py.
"""
import argparse
import contextlib
import errno
import os
import unittest
import unittest.mock as mock

from test_evidence_generator_5040_5042 import ScratchCase, load

FAIL_INDEX_FIRST = 0
FAIL_INDEX_LAST = 2
DESCRIPTOR_COUNT = 3


REAL_CLOSE = os.close


class CloseAll7876(ScratchCase):
    def setUp(self):
        super().setUp()
        self.rc = load('run_cert')
        self.owned = set()
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.fds = [self.open_owned() for _ in range(DESCRIPTOR_COUNT)]

    def open_owned(self):
        """Open a descriptor whose release is registered once; release is idempotent."""
        fd = os.open(os.devnull, os.O_RDONLY)
        self.owned.add(fd)
        self.stack.callback(self.release, fd)
        return fd

    def release(self, fd):
        """Close fd with the real os.close only if the test still owns it and it is still open."""
        if fd in self.owned and not self.closed(fd):
            REAL_CLOSE(fd)
        self.owned.discard(fd)

    def closed(self, fd):
        try:
            os.fstat(fd)
        except OSError as e:
            return e.errno == errno.EBADF
        return False

    def failing_close(self, fail_for):
        real = os.close
        attempts = []

        def close(fd):
            attempts.append(fd)
            real(fd)
            if fd == fail_for:
                raise OSError(errno.EBADF, 'injected close failure')

        return close, attempts

    def test_all_descriptors_closed_and_first_error_reraised_7876(self):
        close, attempts = self.failing_close(self.fds[FAIL_INDEX_FIRST])
        with mock.patch.object(os, 'close', close):
            with self.assertRaises(OSError) as ctx:
                self.rc.close_all(self.fds)
        self.assertEqual(ctx.exception.errno, errno.EBADF)
        self.assertEqual(attempts, self.fds)
        self.assertTrue(all(self.closed(fd) for fd in self.fds))

    def test_first_error_wins_over_later_errors_7876(self):
        real = os.close

        def close(fd):
            real(fd)
            raise OSError(errno.EBADF, 'first' if fd == self.fds[FAIL_INDEX_FIRST] else 'later')

        with mock.patch.object(os, 'close', close):
            with self.assertRaises(OSError) as ctx:
                self.rc.close_all(self.fds)
        self.assertEqual(ctx.exception.strerror, 'first')
        self.assertTrue(all(self.closed(fd) for fd in self.fds))

    def test_no_error_when_all_close_7876(self):
        self.rc.close_all(self.fds)
        self.assertTrue(all(self.closed(fd) for fd in self.fds))

    def test_run_releases_through_close_all_7876(self):
        wt = self.dir / 'checkout'
        wt.mkdir()
        runner = self.rc.Run(argparse.Namespace(
            tip='0' * 40, wt=str(wt), outd=str(self.dir / 'out'),
            leg='gates', targets=str(self.dir / 'targets'), tmpdir=str(self.dir / 'scratch')))
        seen = []
        real = self.rc.close_all
        with mock.patch.object(self.rc, 'close_all', lambda fds: (seen.append(list(fds)), real(fds))[1]):
            code = runner.run(['true'], self.dir / 'child.out', gate=False)
        self.assertEqual(code, 0)
        self.assertEqual(len(seen), 1)
        self.assertGreaterEqual(len(seen[0]), 2, 'private directories and guarded roots are closed together')


if __name__ == '__main__':
    unittest.main()
