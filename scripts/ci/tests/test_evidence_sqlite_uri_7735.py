"""Real SQLite filenames versus the captured, owned fake-root audit guard (#7735)."""
import os
import sqlite3
import unittest
from urllib.parse import quote

import tmp_runtime_guard_7393 as guard
from test_evidence_generator_5040_5042 import ScratchCase


class SqliteUri7735(ScratchCase):
    def setUp(self):
        super().setUp()
        self.fake = self.dir / "fake-root"
        self.fake.mkdir()

    def check_database(self, database, actual, blocked=True, uri=True):
        # All connections target only this explicitly owned fixture directory.
        self.assertTrue(actual.is_relative_to(self.dir))
        sqlite3.connect(database, uri=uri).close()
        self.assertTrue(actual.is_file(), str(actual))
        with guard.captured(self.fake) as sink:
            if blocked:
                with self.assertRaises(guard.TmpRootViolation):
                    sqlite3.connect(database, uri=uri).close()
            else:
                sqlite3.connect(database, uri=uri).close()
        self.assertEqual(bool(sink), blocked)
        if blocked:
            self.assertIn("sqlite3.connect", sink[0])

    def test_file_uri_real_destination_7735(self):
        for name, make_uri in (
                ("query.sqlite", lambda p: "file:" + str(p) + "?mode=rwc"),
                ("space ?#%.sqlite", lambda p: p.as_uri() + "?mode=rwc"),
                ("fragment.sqlite", lambda p: p.as_uri() + "#ignored"),
                ("local.sqlite", lambda p: "file://localhost" + quote(str(p)) + "?mode=rwc"),
                ("nul.sqlite", lambda p: p.as_uri() + "%00ignored?mode=rwc")):
            with self.subTest(name=name):
                actual = self.fake / name
                self.check_database(make_uri(actual), actual)

    def test_relative_file_uri_7735(self):
        actual = self.fake / "relative.sqlite"
        database = "file:" + quote(os.path.relpath(actual)) + "?mode=rwc"
        self.check_database(database, actual)

    def test_ordinary_filename_keeps_query_and_escapes_7735(self):
        actual = self.fake / "ordinary?mode=rwc%23.sqlite"
        self.check_database(str(actual), actual, uri=False)

    def test_ordinary_query_is_not_stripped_into_root_7735(self):
        actual = self.dir / "fake-root?ordinary.sqlite"
        self.check_database(str(actual), actual, blocked=False, uri=False)

    def test_outside_root_uri_and_ordinary_controls_7735(self):
        for uri in (False, True):
            actual = self.dir / ("outside-%s.sqlite" % uri)
            database = actual.as_uri() + "?mode=rwc" if uri else str(actual)
            self.check_database(database, actual, blocked=False, uri=uri)

    def test_no_audit_event_operations_are_documented_7735(self):
        for operation in ("os.mkfifo", "os.mknod"):
            self.assertIn(operation, guard.__doc__)
        self.assertIn("no audit event", guard.__doc__)


if __name__ == "__main__":
    unittest.main()
