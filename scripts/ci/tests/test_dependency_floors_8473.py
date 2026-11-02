#!/usr/bin/env python3
"""Tests for scripts/check-dependency-floors.py (#8473 item 5).

Run: python3 -m unittest discover -s scripts/ci/tests
Python 3.9+, standard library only. Scratch files live under .local-runs/.
"""
import contextlib
import importlib.util
import io
import json
import shutil
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
SCRATCH_ROOT = REPO / ".local-runs"
spec = importlib.util.spec_from_file_location("floors", REPO / "scripts" / "check-dependency-floors.py")
floors = importlib.util.module_from_spec(spec)
spec.loader.exec_module(floors)

TODAY = "2026-11-02"
LOCK = '''version = 4

[[package]]
name = "alpha"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "abc"

[[package]]
name = "beta"
version = "2.5.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
dependencies = [
 "alpha",
]

[[package]]
name = "ai-memory"
version = "1.0.0"
'''


def vuln(vid, fixed, aliases=()):
    return {"id": vid, "aliases": list(aliases), "affected": [{
        "package": {"name": "alpha", "ecosystem": "crates.io"},
        "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": fixed}]}]}]}


def accepted(vid, review_by="2026-11-16", package="alpha", aliases=None, extra=""):
    alias = "aliases = [%s]\n" % ", ".join('"%s"' % a for a in aliases) if aliases else ""
    return ('[[accepted]]\nid = "%s"\n%spackage = "%s"\nrationale = "test"\n'
            'review_by = "%s"\ntracking_issue = 8473\n%s\n') % (vid, alias, package, review_by, extra)


class Gate(unittest.TestCase):
    def setUp(self):
        SCRATCH_ROOT.mkdir(exist_ok=True)
        self.dir = Path(__import__("tempfile").mkdtemp(dir=str(SCRATCH_ROOT)))
        self.addCleanup(shutil.rmtree, str(self.dir), True)
        (self.dir / "Cargo.lock").write_text(LOCK)

    def run_gate(self, vulns, hits, acc, extra=()):
        (self.dir / "osv.json").write_text(json.dumps({"hits": hits, "vulns": vulns}))
        (self.dir / "acc.toml").write_text(acc)
        out, err = io.StringIO(), io.StringIO()
        argv = ["--lock", str(self.dir / "Cargo.lock"), "--accepted", str(self.dir / "acc.toml"),
                "--offline", "--osv-json", str(self.dir / "osv.json"), "--today", TODAY] + list(extra)
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = floors.main(argv)
        return rc, out.getvalue(), err.getvalue()

    def test_lock_parser_reads_registry_packages_only(self):
        self.assertEqual(floors.parse_lock(LOCK), [("alpha", "1.0.0"), ("beta", "2.5.0")])

    def test_fixed_version_is_no_finding(self):
        rc, out, _ = self.run_gate({"V1": vuln("V1", "0.9.0")}, {"alpha@1.0.0": ["V1"]}, "")
        self.assertEqual(rc, 0, out)
        self.assertIn("0 findings", out)

    def test_accepted_finding_passes(self):
        rc, out, _ = self.run_gate({"V1": vuln("V1", "1.2.0")}, {"alpha@1.0.0": ["V1"]}, accepted("V1"))
        self.assertEqual(rc, 0, out)
        self.assertIn("accepted=yes 2026-11-16", out)
        self.assertIn("1 findings, 1 accepted, 0 unaccepted", out)

    def test_uncovered_finding_fails(self):
        rc, out, _ = self.run_gate({"V1": vuln("V1", "1.2.0")}, {"alpha@1.0.0": ["V1"]}, "")
        self.assertEqual(rc, 1)
        self.assertIn("floor: V1 alpha 1.0.0 fixed_in=1.2.0", out)
        self.assertIn("accepted=no", out)

    def test_expired_acceptance_fails(self):
        rc, out, _ = self.run_gate({"V1": vuln("V1", "1.2.0")}, {"alpha@1.0.0": ["V1"]},
                                   accepted("V1", review_by="2026-11-01"))
        self.assertEqual(rc, 1)
        self.assertIn("expired on 2026-11-01", out)

    def test_review_date_today_is_still_valid(self):
        rc, out, _ = self.run_gate({"V1": vuln("V1", "1.2.0")}, {"alpha@1.0.0": ["V1"]},
                                   accepted("V1", review_by=TODAY))
        self.assertEqual(rc, 0, out)

    def test_alias_match_covers_ghsa_record(self):
        v = vuln("GHSA-aaaa-bbbb-cccc", "1.2.0", aliases=["RUSTSEC-2026-1"])
        rc, out, _ = self.run_gate({"GHSA-aaaa-bbbb-cccc": v}, {"alpha@1.0.0": ["GHSA-aaaa-bbbb-cccc"]},
                                   accepted("RUSTSEC-2026-1"))
        self.assertEqual(rc, 0, out)

    def test_acceptance_for_other_package_does_not_cover(self):
        rc, _, _ = self.run_gate({"V1": vuln("V1", "1.2.0")}, {"alpha@1.0.0": ["V1"]},
                                 accepted("V1", package="beta"))
        self.assertEqual(rc, 1)

    def test_stale_acceptance_warns_without_failing(self):
        rc, out, _ = self.run_gate({}, {}, accepted("V9"))
        self.assertEqual(rc, 0, out)
        self.assertIn("warning: stale acceptance V9", out)

    def test_malformed_acceptance_fails(self):
        for bad in ('[[accepted]]\nid = "V1"\n', accepted("V1", review_by="soon"),
                    accepted("V1", extra="surprise = 1")):
            rc, _, err = self.run_gate({}, {}, bad)
            self.assertEqual(rc, 1, bad)
            self.assertIn("acceptance file problem", err)

    def test_last_batch_is_queried(self):
        lock = LOCK + '\n[[package]]\nname = "gamma"\nversion = "3.0.0"\nsource = "registry+x"\n'
        (self.dir / "Cargo.lock").write_text(lock)
        v = vuln("V1", "1.2.0")
        v["affected"][0]["package"]["name"] = "gamma"
        v["affected"][0]["ranges"][0]["events"][1]["fixed"] = "3.5.0"
        rc, out, _ = self.run_gate({"V1": v}, {"gamma@3.0.0": ["V1"]}, "", extra=["--batch-size", "2"])
        self.assertEqual(rc, 1)
        self.assertIn("floor: V1 gamma 3.0.0", out)

    def test_network_failure_without_offline_fails_closed(self):
        (self.dir / "acc.toml").write_text("")
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            rc = floors.main(["--lock", str(self.dir / "Cargo.lock"), "--accepted", str(self.dir / "acc.toml"),
                              "--osv-url", "http://127.0.0.1:9", "--retries", "1", "--backoff", "0"])
        self.assertEqual(rc, 1)
        self.assertIn("failed after 2 attempts", err.getvalue())

    def test_audit_json_is_merged_by_id(self):
        audit = {"vulnerabilities": {"list": [{"advisory": {"id": "RUSTSEC-9", "aliases": []},
                                              "package": {"name": "beta", "version": "2.5.0"},
                                              "versions": {"patched": [">=3.0.0"]}}]}, "warnings": {}}
        (self.dir / "audit.json").write_text(json.dumps(audit))
        rc, out, _ = self.run_gate({}, {}, "", extra=["--audit-json", str(self.dir / "audit.json")])
        self.assertEqual(rc, 1)
        self.assertIn("floor: RUSTSEC-9 beta 2.5.0 fixed_in=>=3.0.0", out)


if __name__ == "__main__":
    unittest.main()
