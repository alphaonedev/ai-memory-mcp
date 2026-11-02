#!/usr/bin/env python3
"""Tests for scripts/check-dependency-floors.py (#8473 item 5).

Run: python3 -m unittest discover -s scripts/ci/tests
Python 3.12+, standard library only. Scratch files live under .local-runs/.
"""
import contextlib
import http.server
import importlib.util
import io
import json
import re
import shutil
import threading
import unittest
import urllib.request
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


class GateBase(unittest.TestCase):
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


class Gate(GateBase):
    def test_lock_parser_reads_registry_packages_only(self):
        self.assertEqual(floors.parse_lock(LOCK), [("alpha", "1.0.0"), ("beta", "2.5.0")])

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
                              "--osv-url", "https://127.0.0.1:9", "--retries", "1", "--backoff", "0"])
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


def detail(events, name="alpha", rtype="SEMVER", versions=None, aliases=()):
    """OSV advisory detail with one affected package and one range."""
    aff = {"package": {"name": name, "ecosystem": "crates.io"},
           "ranges": [{"type": rtype, "events": events}]}
    if versions is not None:
        aff["versions"] = versions
    return {"id": "V1", "aliases": list(aliases), "affected": [aff]}


class RangeWalk(unittest.TestCase):
    """affected_fixed_in: the local walk only computes the fixed version."""

    def fixed(self, events, version, **kw):
        return floors.affected_fixed_in(detail(events, **kw), "alpha", version)

    def test_numeric_not_lexical_compare_r4(self):
        ev = [{"introduced": "0"}, {"fixed": "1.10.0"}]
        self.assertEqual(self.fixed(ev, "1.9.0"), "1.10.0")
        ev = [{"introduced": "0"}, {"fixed": "1.9.0"}]
        self.assertIsNone(self.fixed(ev, "1.10.0"))

    def test_open_range_without_fixed_is_affected_r3(self):
        ev = [{"introduced": "2.0.0"}]
        self.assertEqual(self.fixed(ev, "3.1.0"), "none")
        self.assertIsNone(self.fixed(ev, "1.9.9"))

    def test_fixed_then_reopened_range(self):
        ev = [{"introduced": "0"}, {"fixed": "1.2.0"}, {"introduced": "1.5.0"}]
        self.assertEqual(self.fixed(ev, "1.1.0"), "1.2.0")
        self.assertIsNone(self.fixed(ev, "1.3.0"))
        self.assertEqual(self.fixed(ev, "1.6.0"), "none")

    def test_last_affected_is_inclusive_r6(self):
        ev = [{"introduced": "1.0.0"}, {"last_affected": "1.4.0"}]
        self.assertEqual(self.fixed(ev, "1.4.0"), "none")
        self.assertEqual(self.fixed(ev, "1.0.0"), "none")
        self.assertIsNone(self.fixed(ev, "1.4.1"))
        self.assertIsNone(self.fixed(ev, "0.9.0"))

    def test_versions_only_record_r7(self):
        d = {"affected": [{"package": {"name": "alpha", "ecosystem": "crates.io"},
                           "versions": ["1.2.3", "1.2.4"]}]}
        self.assertEqual(floors.affected_fixed_in(d, "alpha", "1.2.4"), "none")
        self.assertIsNone(floors.affected_fixed_in(d, "alpha", "1.2.5"))

    def test_build_metadata_is_ignored(self):
        ev = [{"introduced": "0"}, {"fixed": "1.2.4"}]
        self.assertEqual(self.fixed(ev, "1.2.3+build.7"), "1.2.4")

    def test_prerelease_compares_per_semver_section_11(self):
        ev = [{"introduced": "0"}, {"fixed": "2.0.0-rc.2"}]
        self.assertEqual(self.fixed(ev, "2.0.0-rc.1"), "2.0.0-rc.2")
        self.assertIsNone(self.fixed(ev, "2.0.0-rc.2"))
        self.assertIsNone(self.fixed(ev, "2.0.0"))
        ev = [{"introduced": "0"}, {"fixed": "1.0.0-beta.2"}]
        self.assertEqual(self.fixed(ev, "1.0.0-beta.1"), "1.0.0-beta.2")

    def test_vkey_orders_the_semver_example_chain(self):
        chain = ["1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2",
                 "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "1.0.1", "1.10.0", "2.0.0"]
        keys = [floors.vkey(v) for v in chain]
        self.assertEqual(keys, sorted(keys))
        self.assertEqual(len(set(keys)), len(chain))

    def test_git_range_is_not_walked(self):
        d = detail([{"introduced": "0"}, {"fixed": "9.0.0"}], rtype="GIT")
        self.assertIsNone(floors.affected_fixed_in(d, "alpha", "1.0.0"))


class Batching(unittest.TestCase):
    """query_findings batch slicing (R1, R2)."""

    def run_query(self, count, batch_size):
        pkgs = [("p%d" % n, "1.0.0") for n in range(count)]
        seen = []

        def post(path, body):
            seen.append([q["package"]["name"] for q in body["queries"]])
            return {"results": [{} for _ in body["queries"]]}
        floors.query_findings(pkgs, post, lambda path: {}, batch_size)
        return pkgs, seen

    def test_every_package_is_queried_exactly_once_r1(self):
        pkgs, seen = self.run_query(2500, floors.MAX_BATCH)
        flat = [n for chunk in seen for n in chunk]
        self.assertEqual(sorted(flat), sorted(n for n, _ in pkgs))
        self.assertEqual(len(flat), len(set(flat)))

    def test_no_chunk_exceeds_one_thousand_r2(self):
        _, seen = self.run_query(1001, floors.MAX_BATCH)
        self.assertEqual(floors.MAX_BATCH, 1000)
        self.assertEqual([len(c) for c in seen], [1000, 1])

    def test_batch_size_above_the_cap_is_rejected_r2(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            floors.main(["--batch-size", "1001"])


class FailClosed(GateBase):
    """OSV hit is authoritative; every odd OSV shape fails closed."""

    def test_hit_the_local_walk_cannot_place_is_a_finding(self):
        v = vuln("V1", "1.2.0")
        v["affected"][0]["package"]["name"] = "Alpha"
        rc, out, _ = self.run_gate({"V1": v}, {"alpha@1.0.0": ["V1"]}, "")
        self.assertEqual(rc, 1)
        self.assertIn("floor: V1 alpha 1.0.0 fixed_in=unknown", out)

    def test_hit_with_git_range_is_a_finding(self):
        v = detail([{"introduced": "0"}, {"fixed": "abc123"}], rtype="GIT")
        rc, out, _ = self.run_gate({"V1": v}, {"alpha@1.0.0": ["V1"]}, "")
        self.assertEqual(rc, 1)
        self.assertIn("fixed_in=unknown", out)

    def test_hit_on_a_version_the_walk_calls_fixed_is_still_a_finding(self):
        rc, out, _ = self.run_gate({"V1": vuln("V1", "0.9.0")}, {"alpha@1.0.0": ["V1"]}, "")
        self.assertEqual(rc, 1)
        self.assertIn("fixed_in=unknown", out)

    def test_prerelease_hit_is_kept_end_to_end(self):
        lock = LOCK.replace('"2.5.0"', '"2.0.0-rc.1"')
        (self.dir / "Cargo.lock").write_text(lock)
        v = vuln("V1", "2.0.0-rc.2")
        v["affected"][0]["package"]["name"] = "beta"
        rc, out, _ = self.run_gate({"V1": v}, {"beta@2.0.0-rc.1": ["V1"]}, "")
        self.assertEqual(rc, 1)
        self.assertIn("floor: V1 beta 2.0.0-rc.1 fixed_in=2.0.0-rc.2", out)

    def test_withdrawn_hit_is_dropped(self):
        v = vuln("V1", "1.2.0")
        v["withdrawn"] = "2026-01-01T00:00:00Z"
        rc, out, _ = self.run_gate({"V1": v}, {"alpha@1.0.0": ["V1"]}, "")
        self.assertEqual(rc, 0, out)

    def test_no_hit_is_no_finding(self):
        rc, out, _ = self.run_gate({}, {}, "")
        self.assertEqual(rc, 0, out)
        self.assertIn("0 findings", out)

    def test_pagination_token_fails_closed(self):
        reply = {"results": [{"next_page_token": "t"}, {}]}
        with self.assertRaises(floors.OsvError):
            floors.check_batch_response(reply, 2)

    def test_unexpected_result_keys_fail_closed(self):
        for reply in ({"results": [{"vulnerabilities": []}, {}]}, {"results": [[], {}]},
                      {"results": [{}, {}], "extra": 1}, {"results": [{"vulns": "x"}, {}]},
                      {"results": [{"vulns": [{"no_id": 1}]}, {}]}, {"results": [{}]}, [], {}):
            with self.assertRaises(floors.OsvError, msg=repr(reply)):
                floors.check_batch_response(reply, 2)

    def test_well_formed_reply_passes(self):
        reply = {"results": [{"vulns": [{"id": "V1", "modified": "x"}]}, {}]}
        self.assertEqual(len(floors.check_batch_response(reply, 2)), 2)

    def test_gate_rc1_on_paginated_reply(self):
        def post(path, body):
            return {"results": [{"next_page_token": "t"} for _ in body["queries"]]}
        with self.assertRaises(floors.OsvError):
            floors.query_findings([("alpha", "1.0.0")], post, lambda p: {}, 10)


class LockInput(GateBase):
    """Non-registry packages are reported; empty or foreign input is RC_INPUT."""

    GIT_PATH_LOCK = LOCK + (
        '\n[[package]]\nname = "gitdep"\nversion = "0.3.0"\n'
        'source = "git+https://example.invalid/x?rev=abc#abc"\n'
        '\n[[package]]\nname = "paste"\nversion = "1.0.15"\n'
        '\n[[patch.unused]]\nname = "ghost"\nversion = "9.9.9"\n')

    def test_git_and_path_packages_are_reported(self):
        (self.dir / "Cargo.lock").write_text(self.GIT_PATH_LOCK)
        rc, out, _ = self.run_gate({}, {}, "")
        self.assertEqual(rc, 0, out)
        self.assertIn("floor: skipped gitdep 0.3.0 source=git queried=no", out)
        self.assertIn("floor: skipped paste 1.0.15 source=path queried=yes", out)
        self.assertIn("floor: skipped ai-memory 1.0.0 source=path queried=yes", out)
        self.assertNotIn("ghost", out)

    def test_path_package_is_queried_by_name_and_version(self):
        (self.dir / "Cargo.lock").write_text(self.GIT_PATH_LOCK)
        v = vuln("RUSTSEC-2024-0436", "none")
        v["affected"][0]["package"]["name"] = "paste"
        v["affected"][0]["ranges"][0]["events"] = [{"introduced": "0"}]
        rc, out, _ = self.run_gate({"RUSTSEC-2024-0436": v}, {"paste@1.0.15": ["RUSTSEC-2024-0436"]}, "")
        self.assertEqual(rc, 1)
        self.assertIn("floor: RUSTSEC-2024-0436 paste 1.0.15", out)

    def test_git_package_is_not_queried(self):
        (self.dir / "Cargo.lock").write_text(self.GIT_PATH_LOCK)
        v = vuln("V1", "1.0.0")
        v["affected"][0]["package"]["name"] = "gitdep"
        rc, out, _ = self.run_gate({"V1": v}, {"gitdep@0.3.0": ["V1"]}, "")
        self.assertEqual(rc, 0, out)

    def test_empty_lock_is_rc_input(self):
        for text in ("", "not a lock file\n", "[[package]]\nname = \"a\"\nversion = \"1.0.0\"\n",
                     'version = 4\n\n[[package]]\nname = "p"\nversion = "1.0.0"\n'):
            (self.dir / "Cargo.lock").write_text(text)
            rc, _, err = self.run_gate({}, {}, "")
            self.assertEqual(rc, 2, repr(text))
            self.assertIn("not a Cargo.lock", err)

    def test_missing_lock_is_rc_input(self):
        (self.dir / "Cargo.lock").unlink()
        rc, _, _ = self.run_gate({}, {}, "")
        self.assertEqual(rc, 2)

    def test_non_https_osv_url_is_refused_unless_offline(self):
        out, err = io.StringIO(), io.StringIO()
        argv = ["--lock", str(self.dir / "Cargo.lock"), "--accepted", str(self.dir / "acc.toml"),
                "--osv-url", "http://127.0.0.1:9"]
        (self.dir / "acc.toml").write_text("")
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = floors.main(argv)
        self.assertEqual(rc, 2)
        self.assertIn("must be https", err.getvalue())


class Acceptance(GateBase):
    def test_review_by_other_iso_spellings_are_rejected(self):
        for bad in ("20261116", "2026-W47-1", "2026-11-16T00:00", "2026-1-6"):
            rc, _, err = self.run_gate({}, {}, accepted("V1", review_by=bad))
            self.assertEqual(rc, 1, bad)
            self.assertIn("review_by", err)
        rc, _, err = self.run_gate({}, {}, accepted("V1", review_by="x").replace('"x"', "20261116"))
        self.assertEqual(rc, 1)
        self.assertIn("acceptance file problem", err)

    def test_impossible_date_is_rejected(self):
        rc, _, err = self.run_gate({}, {}, accepted("V1", review_by="2026-13-45"))
        self.assertEqual(rc, 1)
        self.assertIn("ISO date", err)

    def test_duplicate_id_and_package_is_rejected(self):
        rc, _, err = self.run_gate({}, {}, accepted("V1") + accepted("V1"))
        self.assertEqual(rc, 1)
        self.assertIn("duplicates", err)

    def test_same_id_for_two_packages_is_allowed(self):
        rc, out, _ = self.run_gate({}, {}, accepted("V1") + accepted("V1", package="beta"))
        self.assertEqual(rc, 0, out)

    def test_acceptance_aliases_are_display_only(self):
        v = vuln("GHSA-aaaa-bbbb-cccc", "1.2.0", aliases=["RUSTSEC-2026-1"])
        rc, out, _ = self.run_gate({"GHSA-aaaa-bbbb-cccc": v}, {"alpha@1.0.0": ["GHSA-aaaa-bbbb-cccc"]},
                                   accepted("OTHER", aliases=["RUSTSEC-2026-1"]))
        self.assertEqual(rc, 1)
        self.assertIn("accepted=no", out)

    def test_accepted_line_names_the_matching_id(self):
        v = vuln("GHSA-aaaa-bbbb-cccc", "1.2.0", aliases=["RUSTSEC-2026-1"])
        rc, out, _ = self.run_gate({"GHSA-aaaa-bbbb-cccc": v}, {"alpha@1.0.0": ["GHSA-aaaa-bbbb-cccc"]},
                                   accepted("RUSTSEC-2026-1"))
        self.assertEqual(rc, 0, out)
        self.assertIn("accepted=yes via RUSTSEC-2026-1", out)


class Transport(unittest.TestCase):
    """http_json: bounded read, no redirect downgrade."""

    def serve(self, handler_cls):
        srv = http.server.HTTPServer(("127.0.0.1", 0), handler_cls)
        thread = threading.Thread(target=srv.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        return "http://127.0.0.1:%d/" % srv.server_address[1]

    def test_oversized_body_fails_closed(self):
        class Big(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                body = b'{"pad": "' + b"a" * 5000 + b'"}'
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass
        url = self.serve(Big)
        saved = floors.MAX_RESPONSE_BYTES
        floors.MAX_RESPONSE_BYTES = 1000
        self.addCleanup(setattr, floors, "MAX_RESPONSE_BYTES", saved)
        with self.assertRaises(floors.OsvError) as ctx:
            floors.http_json(url, None, 2, 0)
        self.assertIn("exceeds", str(ctx.exception))

    def test_read_is_bounded_by_the_cap_plus_one(self):
        calls = []

        class Resp:
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def read(self, size=None):
                calls.append(size)
                return b"{}"

        class Opener:
            def open(self, req, timeout=None):
                return Resp()
        saved = urllib.request.build_opener
        urllib.request.build_opener = lambda *a, **k: Opener()
        self.addCleanup(setattr, urllib.request, "build_opener", saved)
        self.assertEqual(floors.http_json("https://x.invalid/", None, 0, 0), {})
        self.assertEqual(calls, [floors.MAX_RESPONSE_BYTES + 1])

    def test_body_within_the_cap_is_read(self):
        class Small(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                body = b'{"ok": true}'
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass
        self.assertEqual(floors.http_json(self.serve(Small), None, 0, 0), {"ok": True})

    def test_redirect_to_non_https_is_refused(self):
        class Redir(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(302)
                self.send_header("Location", "http://127.0.0.1:9/elsewhere")
                self.end_headers()

            def log_message(self, *args):
                pass
        with self.assertRaises(floors.OsvError) as ctx:
            floors.http_json(self.serve(Redir), None, 2, 0)
        self.assertIn("non-https", str(ctx.exception))

    def test_redirect_handler_allows_https_targets(self):
        handler = floors.HttpsOnlyRedirect()
        req = urllib.request.Request("https://api.osv.dev/v1/vulns/X")
        new = handler.redirect_request(req, io.BytesIO(), 302, "Found", {}, "https://api.osv.dev/v1/vulns/Y")
        self.assertEqual(new.full_url, "https://api.osv.dev/v1/vulns/Y")


class EvaluateOnOwnId(GateBase):
    """R3-1: every OSV record is evaluated on its own id; aliases never union (#8473 round 3)."""

    CVE_A, CVE_B = "CVE-2026-100001", "CVE-2099-0001"

    def chain(self):
        vulns = {
            "RUSTSEC-2026-0429": vuln("RUSTSEC-2026-0429", "1.2.0", ["GHSA-q7v9-x93c-xqv3", self.CVE_A]),
            "GHSA-aaaa-aaaa-aaaa": vuln("GHSA-aaaa-aaaa-aaaa", "1.2.0", [self.CVE_A, self.CVE_B]),
            "GHSA-bbbb-bbbb-bbbb": vuln("GHSA-bbbb-bbbb-bbbb", "1.2.0", [self.CVE_B]),
        }
        return vulns, {"alpha@1.0.0": sorted(vulns)}

    def test_chain_of_shared_cves_is_not_accepted(self):
        vulns, hits = self.chain()
        rc, out, _ = self.run_gate(vulns, hits, accepted("RUSTSEC-2026-0429"))
        self.assertEqual(rc, 1, out)
        self.assertIn("floor: GHSA-aaaa-aaaa-aaaa alpha 1.0.0 fixed_in=1.2.0", out)
        self.assertIn("floor: GHSA-bbbb-bbbb-bbbb alpha 1.0.0 fixed_in=1.2.0", out)
        for line in out.splitlines():
            if line.startswith("floor: GHSA-aaaa") or line.startswith("floor: GHSA-bbbb"):
                self.assertTrue(line.endswith("accepted=no"), line)
        self.assertIn("2 unaccepted", out)

    def test_one_hop_record_sharing_only_a_cve_is_not_accepted(self):
        vulns, hits = self.chain()
        del vulns["GHSA-bbbb-bbbb-bbbb"]
        hits = {"alpha@1.0.0": sorted(vulns)}
        rc, out, _ = self.run_gate(vulns, hits, accepted("RUSTSEC-2026-0429"))
        self.assertEqual(rc, 1, out)
        self.assertIn("1 unaccepted", out)

    def test_directly_linked_records_fold_but_keep_their_own_lines(self):
        vulns = {"RUSTSEC-2026-0429": vuln("RUSTSEC-2026-0429", "1.2.0", ["GHSA-q7v9-x93c-xqv3"]),
                 "GHSA-q7v9-x93c-xqv3": vuln("GHSA-q7v9-x93c-xqv3", "1.3.0", ["RUSTSEC-2026-0429"])}
        rc, out, _ = self.run_gate(vulns, {"alpha@1.0.0": sorted(vulns)}, accepted("RUSTSEC-2026-0429"))
        self.assertEqual(rc, 0, out)
        self.assertIn("1 findings, 1 accepted, 0 unaccepted", out)
        self.assertIn("floor: RUSTSEC-2026-0429 alpha 1.0.0 fixed_in=1.2.0", out)
        self.assertIn("floor: GHSA-q7v9-x93c-xqv3 alpha 1.0.0 fixed_in=1.3.0", out)
        self.assertIn("folded_into=RUSTSEC-2026-0429", out)

    def test_one_way_link_leaves_the_folded_record_unaccepted(self):
        vulns = {"RUSTSEC-2026-1": vuln("RUSTSEC-2026-1", "1.2.0", ["GHSA-xxxx-xxxx-xxxx"]),
                 "GHSA-xxxx-xxxx-xxxx": vuln("GHSA-xxxx-xxxx-xxxx", "1.2.0", [])}
        rc, out, _ = self.run_gate(vulns, {"alpha@1.0.0": sorted(vulns)}, accepted("RUSTSEC-2026-1"))
        self.assertEqual(rc, 1, out)
        self.assertIn("1 findings, 0 accepted, 1 unaccepted", out)
        self.assertIn("floor: GHSA-xxxx-xxxx-xxxx alpha 1.0.0 fixed_in=1.2.0 aliases=- accepted=no", out)

    def test_merge_audit_does_not_fold_through_a_shared_cve(self):
        found = [{"id": "RUSTSEC-2026-0429", "aliases": [self.CVE_A], "package": "alpha",
                  "version": "1.0.0", "fixed_in": "1.2.0"}]
        audit = {"warnings": {"x": [{"advisory": {"id": "GHSA-aaaa-aaaa-aaaa", "aliases": [self.CVE_A]},
                                     "package": {"name": "alpha", "version": "1.0.0"},
                                     "versions": {"patched": []}}]}}
        merged = floors.merge_audit(found, audit)
        self.assertEqual([f["id"] for f in merged], ["RUSTSEC-2026-0429", "GHSA-aaaa-aaaa-aaaa"])
        self.assertEqual(merged[0]["aliases"], [self.CVE_A])

    def test_merge_audit_keeps_a_directly_linked_record_with_its_own_aliases(self):
        found = [{"id": "RUSTSEC-2026-0429", "aliases": ["GHSA-q7v9-x93c-xqv3"], "package": "alpha",
                  "version": "1.0.0", "fixed_in": "1.2.0"}]
        audit = {"warnings": {"x": [{"advisory": {"id": "GHSA-q7v9-x93c-xqv3", "aliases": [self.CVE_A]},
                                     "package": {"name": "alpha", "version": "1.0.0"},
                                     "versions": {"patched": [">=9.9.9"]}}]}}
        merged = floors.merge_audit(found, audit)
        self.assertEqual([f["id"] for f in merged], ["RUSTSEC-2026-0429", "GHSA-q7v9-x93c-xqv3"])
        self.assertEqual(merged[0]["aliases"], ["GHSA-q7v9-x93c-xqv3"])
        self.assertEqual(merged[1]["aliases"], [self.CVE_A])
        self.assertEqual(merged[1]["fixed_in"], ">=9.9.9")

    def test_merge_audit_skips_only_the_same_id_package_and_version(self):
        found = [{"id": "RUSTSEC-9", "aliases": [], "package": "alpha", "version": "1.0.0",
                  "fixed_in": "1.2.0"}]
        audit = {"warnings": {"x": [{"advisory": {"id": "RUSTSEC-9", "aliases": []},
                                     "package": {"name": "alpha", "version": "1.0.0"}}]}}
        self.assertEqual(len(floors.merge_audit(found, audit)), 1)


ZIP_LOCK = """version = 4

[[package]]
name = "zip"
version = "7.2.0"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "zip"
version = "8.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"""
ZIP_RUSTSEC = {"id": "RUSTSEC-2026-0429", "aliases": ["CVE-2026-115909", "GHSA-q7v9-x93c-xqv3"],
               "affected": [{"package": {"name": "zip", "ecosystem": "crates.io"},
                             "ranges": [{"type": "SEMVER",
                                         "events": [{"introduced": "0"}, {"fixed": "9.0.0"}]}]}]}
ZIP_ACCEPTED = ('[[accepted]]\nid = "RUSTSEC-2026-0429"\npackage = "zip"\nrationale = "test"\n'
                'review_by = "2026-11-16"\ntracking_issue = 8472\n')


class AuditOneWayLink(GateBase):
    """merge_audit keeps an audit record that an OSV record links to one way (r3 F1)."""

    def setUp(self):
        super().setUp()
        (self.dir / "Cargo.lock").write_text(ZIP_LOCK)

    def run_zip(self, audit_items, hits):
        (self.dir / "audit.json").write_text(json.dumps({"vulnerabilities": {"list": audit_items}}))
        return self.run_gate({"RUSTSEC-2026-0429": ZIP_RUSTSEC}, hits, ZIP_ACCEPTED,
                             extra=["--audit-json", str(self.dir / "audit.json")])

    def test_one_way_linked_audit_record_is_floored_on_its_own(self):
        item = {"advisory": {"id": "GHSA-q7v9-x93c-xqv3", "aliases": ["CVE-2099-0009"]},
                "package": {"name": "zip", "version": "7.2.0"}, "versions": {"patched": [">=9.9.9"]}}
        rc, out, _ = self.run_zip([item], {"zip@7.2.0": ["RUSTSEC-2026-0429"]})
        self.assertEqual(rc, 1, out)
        self.assertRegex(out, r"floor: GHSA-q7v9-x93c-xqv3 zip 7\.2\.0 .*accepted=no "
                              r"folded_into=RUSTSEC-2026-0429")
        self.assertIn("1 unaccepted", out)

    def test_same_id_on_another_version_gets_its_own_floor_line(self):
        item = {"advisory": {"id": "RUSTSEC-2026-0429", "aliases": []},
                "package": {"name": "zip", "version": "8.0.0"}, "versions": {"patched": [">=9.0.0"]}}
        rc, out, _ = self.run_zip([item], {"zip@7.2.0": ["RUSTSEC-2026-0429"]})
        self.assertRegex(out, r"floor: RUSTSEC-2026-0429 zip 8\.0\.0 ")
        self.assertRegex(out, r"floor: RUSTSEC-2026-0429 zip 7\.2\.0 ")


class WithdrawnAndShapes(GateBase):
    """Withdrawn lines, RFC 3339 check and one named rc-2 line per odd input shape."""

    def test_withdrawn_record_prints_its_own_line(self):
        v = vuln("V1", "1.2.0")
        v["withdrawn"] = "2026-01-01T00:00:00Z"
        rc, out, _ = self.run_gate({"V1": v}, {"alpha@1.0.0": ["V1"]}, "")
        self.assertEqual(rc, 0, out)
        self.assertIn("floor: withdrawn V1 alpha 1.0.0 withdrawn=2026-01-01T00:00:00Z", out)

    def test_withdrawn_that_is_not_rfc3339_fails_closed(self):
        for bad in ("yes", "2026-01-01", "2026-13-01T00:00:00Z", "2026-01-01T25:00:00Z", 1, ["x"], "2026-01-01 00:00:00"):
            v = vuln("V1", "1.2.0")
            v["withdrawn"] = bad
            rc, out, err = self.run_gate({"V1": v}, {"alpha@1.0.0": ["V1"]}, "")
            self.assertEqual(rc, 1, repr(bad))
            self.assertIn("RFC 3339", err)
            self.assertIn("V1", err)

    def test_withdrawn_with_offset_and_fraction_is_accepted(self):
        v = vuln("V1", "1.2.0")
        v["withdrawn"] = "2026-01-01T00:00:00.123+02:00"
        rc, out, _ = self.run_gate({"V1": v}, {"alpha@1.0.0": ["V1"]}, "")
        self.assertEqual(rc, 0, out)

    def assert_input_error(self, rc, err, needle):
        self.assertEqual(rc, 2, err)
        self.assertNotIn("Traceback", err)
        self.assertEqual(len(err.strip().splitlines()), 1, err)
        self.assertIn(needle, err)

    def test_withdrawn_stamp_in_the_future_is_still_live(self):
        v = vuln("V1", "1.2.0")
        v["withdrawn"] = "2026-11-03T00:00:00Z"  # one day after TODAY
        rc, out, _ = self.run_gate({"V1": v}, {"alpha@1.0.0": ["V1"]}, "")
        self.assertEqual(rc, 1, out)
        self.assertIn("1 findings, 0 accepted, 1 unaccepted", out)
        self.assertNotIn("floor: withdrawn", out)

    def test_withdrawn_stamp_today_is_withdrawn(self):
        v = vuln("V1", "1.2.0")
        v["withdrawn"] = TODAY + "T00:00:00Z"
        rc, out, _ = self.run_gate({"V1": v}, {"alpha@1.0.0": ["V1"]}, "")
        self.assertEqual(rc, 0, out)

    def test_non_object_affected_shapes_are_a_typed_refusal(self):
        shapes = {
            "affected entry": {"id": "V1", "aliases": [], "affected": ["oops"]},
            "affected list": {"id": "V1", "aliases": [], "affected": "oops"},
            "package": {"id": "V1", "aliases": [], "affected": [{"package": "alpha"}]},
            "ranges": {"id": "V1", "aliases": [], "affected": [{"package": {"name": "alpha"},
                                                                "ranges": "oops"}]},
            "range entry": {"id": "V1", "aliases": [], "affected": [{"package": {"name": "alpha"},
                                                                    "ranges": ["oops"]}]},
        }
        for label, v in shapes.items():
            rc, out, err = self.run_gate({"V1": v}, {"alpha@1.0.0": ["V1"]}, "")
            self.assertEqual(rc, 1, label)
            self.assertNotIn("Traceback", err, label)
            self.assertIn("unparseable OSV record V1:", err, label)
            self.assertEqual(len(err.strip().splitlines()), 1, label)

    def test_audit_aliases_that_are_a_string_are_rc_input(self):
        audit = {"warnings": {"x": [{"advisory": {"id": "RUSTSEC-9", "aliases": "CVE-2099-1"},
                                     "package": {"name": "beta", "version": "2.5.0"}}]}}
        (self.dir / "audit.json").write_text(json.dumps(audit))
        rc, _, err = self.run_gate({}, {}, "", extra=["--audit-json", str(self.dir / "audit.json")])
        self.assert_input_error(rc, err, "aliases")

    def test_empty_range_event_is_rc_input(self):
        v = detail([{"introduced": "0"}, {}])
        v["id"] = "V1"
        rc, _, err = self.run_gate({"V1": v}, {"alpha@1.0.0": ["V1"]}, "")
        self.assert_input_error(rc, err, "malformed range event")

    def test_detail_that_is_a_list_is_rc_input(self):
        rc, _, err = self.run_gate({"V1": []}, {"alpha@1.0.0": ["V1"]}, "")
        self.assert_input_error(rc, err, "V1")

    def test_detail_that_is_a_string_is_rc_input(self):
        rc, _, err = self.run_gate({"V1": "oops"}, {"alpha@1.0.0": ["V1"]}, "")
        self.assert_input_error(rc, err, "not an object")

    def test_missing_osv_json_is_rc_input(self):
        (self.dir / "acc.toml").write_text("")
        out, err = io.StringIO(), io.StringIO()
        argv = ["--lock", str(self.dir / "Cargo.lock"), "--accepted", str(self.dir / "acc.toml"),
                "--offline", "--osv-json", str(self.dir / "absent.json"), "--today", TODAY]
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = floors.main(argv)
        self.assert_input_error(rc, err.getvalue(), "absent.json")

    def test_unparsable_today_is_rc_input(self):
        rc, _, err = self.run_gate({}, {}, "", extra=["--today", "tomorrow"])
        self.assert_input_error(rc, err, "--today")

    def test_audit_advisory_without_id_is_rc_input(self):
        audit = {"warnings": {"x": [{"advisory": {"aliases": []},
                                     "package": {"name": "beta", "version": "2.5.0"}}]}}
        (self.dir / "audit.json").write_text(json.dumps(audit))
        rc, _, err = self.run_gate({}, {}, "", extra=["--audit-json", str(self.dir / "audit.json")])
        self.assert_input_error(rc, err, "without an id")

    def test_missing_audit_json_is_rc_input(self):
        rc, _, err = self.run_gate({}, {}, "", extra=["--audit-json", str(self.dir / "nope.json")])
        self.assert_input_error(rc, err, "nope.json")

    def test_lock_without_version_header_is_rejected(self):
        body = LOCK.split("\n", 2)[2]  # drop the `version = 4` header line and the blank line
        self.assertNotIn("version = 4", body)
        (self.dir / "Cargo.lock").write_text(body)
        self.assertFalse(floors.has_lock_header(body))
        rc, _, err = self.run_gate({}, {}, "")
        self.assertEqual(rc, 2)
        self.assertIn("not a Cargo.lock", err)


class WorkspaceMembers(GateBase):
    """Workspace path members are not sent to OSV by name; vendored path crates are."""

    LOCK2 = LOCK + '\n[[package]]\nname = "paste"\nversion = "1.0.15"\n'

    def test_member_named_in_a_manifest_is_not_queried(self):
        (self.dir / "Cargo.lock").write_text(self.LOCK2)
        (self.dir / "Cargo.toml").write_text('[package]\nname = "ai-memory"\nversion = "1.0.0"\n')
        rc, out, _ = self.run_gate({}, {}, "")
        self.assertEqual(rc, 0, out)
        self.assertIn("floor: skipped ai-memory 1.0.0 source=path queried=no", out)
        self.assertIn("floor: skipped paste 1.0.15 source=path queried=yes", out)

    def test_member_name_hit_is_ignored_but_vendored_path_hit_is_kept(self):
        (self.dir / "Cargo.lock").write_text(self.LOCK2)
        (self.dir / "Cargo.toml").write_text('[package]\nname = "ai-memory"\nversion = "1.0.0"\n')
        v1 = vuln("V1", "2.0.0")
        v1["affected"][0]["package"]["name"] = "ai-memory"
        v2 = vuln("V2", "2.0.0")
        v2["affected"][0]["package"]["name"] = "paste"
        rc, out, _ = self.run_gate({"V1": v1, "V2": v2}, {"ai-memory@1.0.0": ["V1"], "paste@1.0.15": ["V2"]}, "")
        self.assertEqual(rc, 1)
        self.assertNotIn("floor: V1", out)
        self.assertIn("floor: V2 paste 1.0.15", out)

    def test_fuzz_member_is_not_queried(self):
        (self.dir / "fuzz").mkdir()
        (self.dir / "fuzz" / "Cargo.toml").write_text('[package]\nname = "ai-memory-fuzz"\nversion = "0.0.0"\n')
        (self.dir / "Cargo.lock").write_text(self.LOCK2 + '\n[[package]]\nname = "ai-memory-fuzz"\nversion = "0.0.0"\n')
        rc, out, _ = self.run_gate({}, {}, "")
        self.assertIn("floor: skipped ai-memory-fuzz 0.0.0 source=path queried=no", out)


class SurvivorsRound3(GateBase):
    """One test per mutant the first round-3 mutant run left alive."""

    def test_an_acceptance_alias_never_covers_a_record_with_that_id(self):
        # the entry X lists Y as an alias; a record whose own id is Y and whose aliases
        # do not name X is a different advisory and stays unaccepted
        v = vuln("GHSA-yyyy-yyyy-yyyy", "1.2.0")
        rc, out, _ = self.run_gate({"GHSA-yyyy-yyyy-yyyy": v}, {"alpha@1.0.0": ["GHSA-yyyy-yyyy-yyyy"]},
                                   accepted("RUSTSEC-2026-9", aliases=["GHSA-yyyy-yyyy-yyyy"]))
        self.assertEqual(rc, 1, out)
        self.assertIn("accepted=no", out)

    def test_withdrawn_false_is_not_a_timestamp(self):
        d = vuln("V1", "1.2.0")
        d["withdrawn"] = False
        with self.assertRaises(floors.OsvError):
            floors.withdrawn_stamp(d, "V1")

    def test_malformed_aliases_are_rc_input(self):
        d = vuln("V1", "1.2.0")
        d["aliases"] = "CVE-1"
        rc, _, err = self.run_gate({"V1": d}, {"alpha@1.0.0": ["V1"]}, "")
        self.assertEqual(rc, 2, err)
        self.assertIn("malformed aliases", err)

    def test_range_events_are_ordered_before_the_walk(self):
        d = detail([{"fixed": "2.0.0"}, {"introduced": "0"}])
        self.assertEqual(floors.affected_fixed_in(d, "alpha", "1.0.0"), "2.0.0")

    def test_build_metadata_is_ignored_in_the_order(self):
        self.assertEqual(floors.vkey("1.2.0+build.5"), floors.vkey("1.2.0"))
        d = detail([{"introduced": "0"}, {"fixed": "1.2.0"}])
        self.assertIsNone(floors.affected_fixed_in(d, "alpha", "1.2.0+build.5"))

    def test_detail_that_is_not_an_object_is_an_input_error_at_the_walk(self):
        with self.assertRaises(floors.InputError):
            floors.affected_fixed_in([], "alpha", "1.0.0")

    def test_audit_json_that_is_not_an_object_is_an_input_error(self):
        with self.assertRaises(floors.InputError):
            floors.merge_audit([], [])


class FuzzLockMatchesRootLock(unittest.TestCase):
    """The fuzz workspace has its own Cargo.lock (#8473 round 3, R3-3).

    Every package name the two locks share must carry, in fuzz/Cargo.lock, only
    (version, source) pairs that the root lock also carries. The paste patch
    (path source, no registry line) is the case that drifted: root used
    vendor/paste, fuzz resolved registry paste 1.0.15 (RUSTSEC-2024-0436).
    """

    @staticmethod
    def pairs(text):
        rows, cur = [], None
        for raw in text.splitlines():
            line = raw.strip()
            if line == "[[package]]":
                cur = {}
                rows.append(cur)
            elif line.startswith("["):
                cur = None
            elif cur is not None:
                m = re.match(r'^(\w+) = "(.*)"$', line)
                if m:
                    cur[m.group(1)] = m.group(2)
        by_name = {}
        for row in rows:
            if "name" in row and "version" in row:
                by_name.setdefault(row["name"], set()).add((row["version"], row.get("source")))
        return by_name

    def test_shared_packages_have_the_same_version_and_source(self):
        root = self.pairs((REPO / "Cargo.lock").read_text())
        fuzz = self.pairs((REPO / "fuzz" / "Cargo.lock").read_text())
        shared = sorted(set(root) & set(fuzz))
        self.assertGreater(len(shared), 100)
        drift = ["%s fuzz=%s root=%s" % (n, sorted(map(str, fuzz[n] - root[n])), sorted(map(str, root[n])))
                 for n in shared if not fuzz[n] <= root[n]]
        self.assertEqual(drift, [])

    def test_paste_comes_from_the_vendored_copy_in_both_locks(self):
        for lock in ("Cargo.lock", "fuzz/Cargo.lock"):
            got = self.pairs((REPO / lock).read_text())["paste"]
            self.assertEqual(got, {("1.0.15", None)}, lock)

    def test_fuzz_manifest_patches_paste_to_vendor(self):
        text = (REPO / "fuzz" / "Cargo.toml").read_text()
        self.assertIn("[patch.crates-io]", text)
        self.assertIn('paste = { path = "../vendor/paste" }', text)


if __name__ == "__main__":
    unittest.main()
