#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""scripts/ci/pr_retarget_check.py refuses a landing after a stale base change (#8332).

Offline. Cases a-f feed fixtures through ``--json-dir`` (timeline.json plus runs.json).
The live-path cases (``LivePath``) run the script WITHOUT ``--json-dir`` against a stub
``gh`` (fixtures/pr_retarget_check_8332/stub_bin/gh) placed first on PATH, so the page
loop and the gh failure handling execute for real; no network call is made.

Stdlib only. Run: ``python3 -I scripts/test/test_pr_retarget_check_8332.py``.
"""
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import unittest
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "ci" / "pr_retarget_check.py"
FIX = ROOT / "scripts" / "test" / "fixtures" / "pr_retarget_check_8332"
HEAD = "b" * 40
STUB_BIN = FIX / "stub_bin"
SCRATCH = ROOT / ".local-runs"


def _load_module():
    spec = importlib.util.spec_from_file_location("pr_retarget_check_under_test", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

PAGE = 100
T_CHANGE = "2026-10-30T12:00:00Z"
T_BEFORE = "2026-10-30T10:00:00Z"
T_AFTER = "2026-10-30T14:00:00Z"


RETARGET = _load_module()


def run_check(case: str):
    return subprocess.run(
        [sys.executable, "-I", str(SCRIPT), "--repo", "o/r", "--pr", "1", "--head", HEAD,
         "--json-dir", str(FIX / case)],
        capture_output=True, text=True, check=False,
    )


class PrRetargetCheck8332(unittest.TestCase):
    def test_a_no_base_change(self):
        r = run_check("a_no_change")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("retarget-check: no base change", r.stdout)

    def test_b_base_change_older_than_both_runs(self):
        r = run_check("b_change_older")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_c_base_change_newer_than_ci_run(self):
        r = run_check("c_ci_stale")
        self.assertEqual(r.returncode, 65, r.stdout + r.stderr)
        self.assertIn("REFUSE: base retargeted at 2026-10-30T12:00:00Z after the latest pull_request run of ci.yml", r.stdout)

    def test_d_base_change_newer_than_coverage_run_only(self):
        r = run_check("d_cov_stale")
        self.assertEqual(r.returncode, 65, r.stdout + r.stderr)
        self.assertIn("run of coverage.yml", r.stdout)

    def test_e_change_on_second_timeline_page(self):
        r = run_check("e_two_pages")
        self.assertEqual(r.returncode, 65, r.stdout + r.stderr)

    def test_f_gh_failure_is_a_tool_error(self):
        r = run_check("f_gh_failure")
        self.assertEqual(r.returncode, 70, r.stdout + r.stderr)


def filler(n: int) -> list:
    return [{"event": "commented", "created_at": "2026-10-30T09:00:00Z"} for _ in range(n)]


def change(stamp: str) -> dict:
    return {"event": "base_ref_changed", "created_at": stamp}


def runs_at(stamp: str) -> list:
    return [{"databaseId": 7, "createdAt": stamp, "conclusion": "success", "status": "completed"}]


class LivePath(unittest.TestCase):
    """The script without --json-dir, talking to the stub gh."""

    def setUp(self):
        SCRATCH.mkdir(exist_ok=True)
        self.stub = SCRATCH / f"stub-{uuid.uuid4().hex[:8]}"
        self.stub.mkdir()
        self.addCleanup(shutil.rmtree, self.stub, True)
        # decision (round 5, REVIEW-8332-code-r4 INFO, REVIEW-8332-security-r4 INFO): the child PATH is the
        # stub dir plus a scratch bin holding only the two symlinks the stub's `env python3` shebang needs,
        # so no real gh exists anywhere on it; /usr/bin and /bin are left out.
        self.sysbin = self.stub / "bin"
        self.sysbin.mkdir()
        (self.sysbin / "python3").symlink_to(sys.executable)
        (self.sysbin / "env").symlink_to(shutil.which("env"))

    def put(self, key: str, value, suffix: str = "json"):
        text = json.dumps(value) if suffix == "json" else value
        (self.stub / f"{key}.{suffix}").write_text(text, encoding="utf-8")

    def runs(self, ci: str, cov: str):
        self.put("runs_ci.yml", runs_at(ci))
        self.put("runs_coverage.yml", runs_at(cov))

    def child_env(self, extra=None) -> dict:
        """Environment built from scratch: no inherited gh credentials, host or config."""
        env = {"PATH": os.pathsep.join([str(STUB_BIN), str(self.sysbin)]),
               "HOME": str(self.stub), "GH_STUB_DIR": str(self.stub)}
        env.update(extra or {})
        for banned in ("GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN", "GH_HOST", "GH_CONFIG_DIR"):
            self.assertNotIn(banned, env)
        return env

    def run_live(self, extra=None):
        env = self.child_env(extra)
        found = shutil.which("gh", path=env["PATH"])
        stub = STUB_BIN / "gh"
        self.assertIsNotNone(found, "gh does not resolve on the child PATH")
        self.assertEqual(Path(found).resolve(), stub.resolve(), f"{self.id()}: gh is not the stub")
        self.assertTrue(os.access(stub, os.X_OK), f"{self.id()}: the stub gh is not executable")
        self.assertEqual([p for p in sorted(self.sysbin.iterdir())], [self.sysbin / "env", self.sysbin / "python3"])
        return subprocess.run(
            [sys.executable, "-I", str(SCRIPT), "--repo", "o/r", "--pr", "1", "--head", HEAD],
            capture_output=True, text=True, check=False, env=env)

    def requests(self) -> list:
        log = self.stub / "requests.log"
        return log.read_text().split() if log.is_file() else []

    def test_a_base_change_on_page_two_refuses(self):
        self.put("timeline_page1", filler(PAGE))
        self.put("timeline_page2", filler(2) + [change(T_CHANGE)])
        self.runs(T_BEFORE, T_BEFORE)
        r = self.run_live()
        self.assertEqual(r.returncode, 65, r.stdout + r.stderr)
        self.assertIn(f"REFUSE: base retargeted at {T_CHANGE}", r.stdout)
        self.assertEqual(self.requests()[:2], ["timeline_page1", "timeline_page2"])

    def test_b_exact_full_page_then_empty_page(self):
        self.put("timeline_page1", filler(PAGE - 1) + [change(T_CHANGE)])
        self.put("timeline_page2", [])
        self.runs(T_AFTER, T_AFTER)
        r = self.run_live()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn(f"retarget-check: base changed at {T_CHANGE}", r.stdout)
        self.assertEqual(self.requests()[:2], ["timeline_page1", "timeline_page2"])

    def test_c_gh_nonzero_is_a_tool_error(self):
        (self.stub / "timeline_page1.rc").write_text("1")
        r = self.run_live()
        self.assertEqual(r.returncode, 70, r.stdout + r.stderr)
        self.assertNotIn("no base change", r.stdout)
        self.assertEqual(self.requests(), ["timeline_page1"])

    def test_c2_gh_nonzero_on_runs_is_a_tool_error(self):
        self.put("timeline_page1", [change(T_CHANGE)])
        self.put("runs_ci.yml", runs_at(T_AFTER))
        (self.stub / "runs_coverage.yml.rc").write_text("4")
        r = self.run_live()
        self.assertEqual(r.returncode, 70, r.stdout + r.stderr)
        self.assertEqual(self.requests(), ["timeline_page1", "runs_ci.yml", "runs_coverage.yml"])

    def test_d_gh_non_json_is_a_tool_error(self):
        self.put("timeline_page1", "<html>rate limited</html>", "raw")
        r = self.run_live()
        self.assertEqual(r.returncode, 70, r.stdout + r.stderr)
        self.assertNotIn("no base change", r.stdout)
        self.assertEqual(self.requests(), ["timeline_page1"])

    def test_e_two_base_changes_newest_first_use_the_latest(self):
        self.put("timeline_page1", [change(T_AFTER), change(T_BEFORE)])
        self.runs("2026-10-30T13:00:00Z", "2026-10-30T13:00:00Z")
        r = self.run_live()
        self.assertEqual(r.returncode, 65, r.stdout + r.stderr)
        self.assertIn(f"REFUSE: base retargeted at {T_AFTER}", r.stdout)

    def test_e2_two_base_changes_oldest_first_use_the_latest(self):
        # The REST timeline is oldest first: the latest change is the LAST one listed.
        self.put("timeline_page1", [change(T_BEFORE), change(T_AFTER)])
        self.runs("2026-10-30T13:00:00Z", "2026-10-30T13:00:00Z")
        r = self.run_live()
        self.assertEqual(r.returncode, 65, r.stdout + r.stderr)
        self.assertIn(f"REFUSE: base retargeted at {T_AFTER}", r.stdout)

    def test_g_non_list_timeline_page_is_a_tool_error(self):
        self.put("timeline_page1", {"message": "Server Error"})
        r = self.run_live()
        self.assertEqual(r.returncode, 70, r.stdout + r.stderr)
        self.assertNotIn("no base change", r.stdout)
        self.assertIn("not a list", r.stderr)

    def test_h_base_change_without_created_at_is_a_tool_error(self):
        self.put("timeline_page1", [{"event": "base_ref_changed"}])
        self.runs(T_AFTER, T_AFTER)
        r = self.run_live()
        self.assertEqual(r.returncode, 70, r.stdout + r.stderr)
        self.assertIn("no created_at", r.stderr)

    def test_i_page_cap_is_a_tool_error(self):
        # The cap is lowered to 2 through PR_RETARGET_MAX_PAGES; the change sits on page 3.
        self.put("timeline_page1", filler(PAGE))
        self.put("timeline_page2", filler(PAGE))
        self.put("timeline_page3", [change(T_CHANGE)])
        self.runs(T_BEFORE, T_BEFORE)
        r = self.run_live({"PR_RETARGET_MAX_PAGES": "2"})
        self.assertEqual(r.returncode, 70, r.stdout + r.stderr)
        self.assertIn("page cap", r.stderr)
        self.assertEqual(self.requests(), ["timeline_page1", "timeline_page2"])

    def test_j_page_cap_override_cannot_raise_the_cap(self):
        # The resolution function itself: the override may only LOWER the default cap.
        default = RETARGET.MAX_PAGES_DEFAULT
        self.assertEqual(default, 200)
        for raw in ("201", "99999", "0", "-3", "garbage", "", "200", "2.5", None):
            self.assertEqual(RETARGET.resolve_max_pages(raw), default, repr(raw))
        for raw, want in (("2", 2), ("199", 199), ("1", 1)):
            self.assertEqual(RETARGET.resolve_max_pages(raw), want, raw)
        # Round 6 (REVIEW-8332-code-r5 I1): int() strips whitespace; a padded value still only LOWERS the cap.
        self.assertEqual(RETARGET.resolve_max_pages(" 2 "), 2)

    def test_j2_raised_cap_override_still_stops_at_the_default_through_the_script(self):
        # Live path: a one-page timeline, a 99999 override; the answer is unchanged (cap not raised).
        self.put("timeline_page1", [change(T_CHANGE)])
        self.runs(T_AFTER, T_AFTER)
        r = self.run_live({"PR_RETARGET_MAX_PAGES": "99999"})
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_h2(self):
        # Every base-change stamp must parse (round 6, REVIEW-8332-code-r5 F2, REVIEW-8332-security-r5 S11):
        # a padded or space-separated later stamp sorted below the canonical 10:00 one as a string.
        stamped = change("2026-10-30T10:00:00Z")
        for events, why in (([stamped, {"event": "base_ref_changed"}], "no created_at"),
                            ([{"event": "base_ref_changed"}, stamped], "no created_at"),
                            ([stamped, {"event": "base_ref_changed", "created_at": ""}], "no created_at"),
                            ([stamped, {"event": "base_ref_changed", "created_at": None}], "no created_at"),
                            ([stamped, change("   ")], "unparsable created_at"),
                            ([stamped, change(" 2026-10-30T13:00:00Z")], "unparsable created_at"),
                            ([stamped, change("2026-10-30 13:00:00Z")], "unparsable created_at"),
                            ([stamped, change("garbage")], "unparsable created_at"),
                            # round 7 (REVIEW-8332-code-r6 INFO-1): strptime alone accepted these three
                            ([stamped, change("2026-10-30t13:00:00z")], "unparsable created_at"),
                            ([stamped, change("2026-10-30T3:00:00Z")], "unparsable created_at"),
                            ([stamped, change("\u0662\u0660\u0662\u0666-10-30T13:00:00Z")], "unparsable created_at"),
                            # round 7 (REVIEW-8332-security-r6 INFO): a number is named as such, not as missing;
                            # round 8 (REVIEW-8332-code-r7 INFO-1): the kind is named without an article
                            ([stamped, {"event": "base_ref_changed", "created_at": 1793365200}],
                             "created_at of kind int")):
            self.put("timeline_page1", events)
            self.runs(T_AFTER, T_AFTER)
            r = self.run_live()
            self.assertEqual(r.returncode, 70, f"{events}: {r.stdout}{r.stderr}")
            self.assertIn(why, r.stderr)

    def test_h3_unparsable_run_stamp_is_a_tool_error(self):
        # An unparsable run createdAt is refused, never skipped, even beside a valid newer run.
        self.put("timeline_page1", [change(T_CHANGE)])
        for bad in (" 2026-10-30T15:00:00Z", "2026-10-30 15:00:00Z", None, "2026-10-30t15:00:00z"):
            self.put("runs_ci.yml", runs_at(T_AFTER) + [{"databaseId": 8, "createdAt": bad}])
            self.put("runs_coverage.yml", runs_at(T_AFTER))
            r = self.run_live()
            self.assertEqual(r.returncode, 70, f"{bad!r}: {r.stdout}{r.stderr}")
            self.assertIn("ci.yml run has", r.stderr)

    def test_f_run_in_the_same_second_is_not_newer(self):
        self.put("timeline_page1", [change(T_CHANGE)])
        self.runs(T_CHANGE, T_CHANGE)
        r = self.run_live()
        self.assertEqual(r.returncode, 65, r.stdout + r.stderr)


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
