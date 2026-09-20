# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Exercise the exact Python cleanup body shipped in the workflow."""
import os
from pathlib import Path
import tempfile
import textwrap
import unittest


def workflow_cleanup():
    workflow = Path(__file__).resolve().parents[2] / '.github/workflows/native-federation-f1.yml'
    source = workflow.read_text().split('# BEGIN NATIVE CLEANUP\n', 1)[1]
    source = source.split('          # END NATIVE CLEANUP', 1)[0]
    namespace = {'__name__': 'cleanup_under_test'}
    exec(compile(textwrap.dedent(source), str(workflow), 'exec'), namespace)
    return namespace


class WorkflowCleanupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=os.environ['TMPDIR'])
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.cleanup = workflow_cleanup()
        for parent in ('wt', 'tmp', 'targets'):
            (self.root / parent).mkdir()
        for parent in ('wt', 'tmp'):
            run = self.root / parent / 'e5-ci-123-1'
            (run / 'nested').mkdir(parents=True)
            (run / 'nested' / 'evidence').write_text('owned')
            (self.root / parent / 'e5-ci-123-2').mkdir()
        (self.root / 'targets' / 'e5-native-ci').mkdir()

    def run_cleanup(self, run_id='123', attempt='1'):
        self.cleanup['clean_run'](str(self.root), run_id, attempt)

    def test_exact_trees_removed_siblings_and_cache_retained(self):
        self.run_cleanup()
        for parent in ('wt', 'tmp'):
            self.assertFalse((self.root / parent / 'e5-ci-123-1').exists())
            self.assertTrue((self.root / parent / 'e5-ci-123-2').is_dir())
        self.assertTrue((self.root / 'targets' / 'e5-native-ci').is_dir())
        self.run_cleanup()  # Partial setup / already removed runs are harmless.

    def test_bad_identifiers_cannot_select_parents_or_siblings(self):
        for run_id, attempt in [('..', '1'), ('123', '../2'), ('', '1'), ('123', ''), ('123*', '1'), ('123\n', '1')]:
            with self.subTest(run_id=run_id, attempt=attempt), self.assertRaises(ValueError):
                self.run_cleanup(run_id, attempt)
        self.assertTrue((self.root / 'wt' / 'e5-ci-123-1').is_dir())

    def test_nested_symlink_refused_without_touching_destination(self):
        outside = self.root / 'targets' / 'sentinel'
        outside.write_text('keep')
        (self.root / 'wt' / 'e5-ci-123-1' / 'escape').symlink_to(outside)
        with self.assertRaises(ValueError):
            self.run_cleanup()
        self.assertEqual(outside.read_text(), 'keep')

    def test_parent_symlink_refused(self):
        (self.root / 'wt').rename(self.root / 'real-wt')
        (self.root / 'wt').symlink_to(self.root / 'real-wt', target_is_directory=True)
        with self.assertRaises(OSError):
            self.run_cleanup()
        self.assertTrue((self.root / 'real-wt' / 'e5-ci-123-1').is_dir())

    def test_run_root_symlink_refused(self):
        run = self.root / 'wt' / 'e5-ci-123-1'
        run.rename(self.root / 'saved')
        run.symlink_to(self.root / 'saved', target_is_directory=True)
        with self.assertRaises(ValueError):
            self.run_cleanup()
        self.assertTrue((self.root / 'saved' / 'nested' / 'evidence').is_file())

    def test_work_budget_fails_closed(self):
        self.cleanup['MAX_ENTRIES'] = 1
        with self.assertRaises(ValueError):
            self.run_cleanup()
        self.assertTrue((self.root / 'wt' / 'e5-ci-123-1').is_dir())

    def test_cleanup_always_follows_upload_and_does_not_need_checkout(self):
        workflow = (Path(__file__).resolve().parents[2] / '.github/workflows/native-federation-f1.yml').read_text()
        upload = workflow.index('- name: Upload sanitized native evidence')
        cleanup = workflow.index('- name: Remove exact per-run checkout and scratch')
        self.assertGreater(cleanup, upload)
        self.assertIn('if: always()', workflow[cleanup:])
        self.assertIn('shell: python3 {0}', workflow[cleanup:])


if __name__ == '__main__':
    unittest.main()
