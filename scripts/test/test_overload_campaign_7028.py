#!/usr/bin/env python3
"""Campaign P report and refusal ratchets; stdlib, no server or stress workers."""

import argparse
from collections import Counter
import hashlib
import importlib.util
import json
from pathlib import Path
import sqlite3
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

MODULE = Path(__file__).with_name("overload_campaign.py")
SPEC = importlib.util.spec_from_file_location("overload_campaign", MODULE)
CAMPAIGN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CAMPAIGN)
SCRATCH = MODULE.parents[2] / ".local-runs" / "overload"


def fixture():
    """Recorded-shaped observations, explicitly synthetic (not campaign evidence)."""
    samples = {kind: {"histogram": Counter({1: 100}), "status": Counter({"200": 100})}
               for kind in CAMPAIGN.OPERATIONS}
    return {"backend": "sqlite", "clients": 50, "duration_seconds": 30,
            "operations": CAMPAIGN.summarize(samples), "late_successes": {},
            "shed_delta": 0, "integrity": {"ok": True}, "probe_status": 200,
            "probe_ms": 2, "shed_stable": True, "fd_peak": 100, "fd_limit": 1024,
            "rss_peak_kib": 32000, "cleanup_ok": True}


class Reports(unittest.TestCase):
    def test_nearest_rank_upper_buckets(self):
        self.assertEqual(CAMPAIGN.quantile(Counter({1: 95, 8: 4, 20: 1}), 99), 8)
        self.assertEqual(CAMPAIGN.quantile(Counter({1: 95, 8: 4, 20: 1}), 50), 1)
        self.assertIsNone(CAMPAIGN.quantile(Counter(), 99))

    def test_missing_ceiling_never_claims_all_bounds_pass(self):
        result = CAMPAIGN.evaluate(fixture())
        self.assertFalse(result["all_bounds_hold"])
        self.assertEqual(result["verdict"], "INCOMPLETE")
        self.assertEqual(result["cells"]["P2c"], "PASS")

    def test_one_shed_cannot_excuse_slow_successes(self):
        report = fixture()
        report["shed_delta"] = 1
        report["operations"]["store"]["latency_ms_upper"]["p99"] = 500
        report["late_successes"]["store"] = 20
        self.assertEqual(CAMPAIGN.evaluate(report)["verdict"], "FINDING")

    def test_silent_queue_fails_even_without_late_success_count(self):
        report = fixture()
        report["operations"]["recall"]["latency_ms_upper"]["p99"] = 500
        self.assertEqual(CAMPAIGN.evaluate(report)["verdict"], "FINDING")

    def test_refusals_are_distinct_from_unexpected_responses(self):
        report = fixture()
        report["shed_delta"] = 100
        report["operations"]["store"]["status"] = {"503": 100}
        self.assertEqual(CAMPAIGN.evaluate(report)["faults"], [])
        report["operations"]["store"]["status"] = {"other": 100}
        self.assertEqual(CAMPAIGN.evaluate(report)["verdict"], "FINDING")

    def test_no_traffic_is_not_success(self):
        report = fixture()
        report["operations"]["store"]["count"] = 0
        self.assertEqual(CAMPAIGN.evaluate(report)["verdict"], "FINDING")

    def test_missing_and_exceeded_resources_fail(self):
        for name, value in (("fd_peak", None), ("fd_peak", 1024), ("rss_peak_kib", None)):
            with self.subTest(name=name, value=value):
                report = fixture()
                report[name] = value
                result = CAMPAIGN.evaluate(report)
                self.assertEqual(result["verdict"], "FINDING")
                self.assertEqual(result["cells"]["P2g"], "FINDING")

    def test_recovery_requires_non_exempt_success_and_stable_counter(self):
        for name, value in (("probe_status", 503), ("shed_stable", False), ("probe_ms", 60000)):
            report = fixture()
            report[name] = value
            self.assertEqual(CAMPAIGN.evaluate(report)["verdict"], "FINDING")

    def test_cleanup_must_be_proven(self):
        report = fixture()
        report["cleanup_ok"] = False
        self.assertEqual(CAMPAIGN.evaluate(report)["verdict"], "FINDING")

    def test_markdown_carries_observations_and_sources(self):
        result = CAMPAIGN.markdown(fixture())
        self.assertIn("PERFORMANCE.md:69", result)
        self.assertIn("Clients: 50", result)
        self.assertIn("'p99': 1", result)

    def test_mix_validation(self):
        self.assertEqual(CAMPAIGN.parse_mix("60/30/10"), (60, 30, 10))
        with self.assertRaises(argparse.ArgumentTypeError):
            CAMPAIGN.parse_mix("60/30/0")


class Cleanup(unittest.TestCase):
    def test_workers_share_term_and_kill_deadlines(self):
        with patch.object(CAMPAIGN.atexit, "register"):
            group = CAMPAIGN.Children()
        children = [MagicMock(pid=n) for n in (111, 222)]
        for child in children:
            child.poll.return_value = None
            child.wait.side_effect = [subprocess.TimeoutExpired("fixture", 10), 0]
        with patch.object(CAMPAIGN.os, "killpg") as kill, patch.object(
                CAMPAIGN.time, "monotonic", side_effect=[0, 1, 10, 10, 11, 15]):
            group.stop_group(children)
        self.assertEqual(children[0].wait.call_args_list[0].kwargs["timeout"], 9)
        self.assertEqual(children[1].wait.call_args_list[0].kwargs["timeout"], 0)
        self.assertEqual(children[0].wait.call_args_list[1].kwargs["timeout"], 4)
        self.assertEqual(children[1].wait.call_args_list[1].kwargs["timeout"], 0)
        self.assertEqual(kill.call_count, 4)
        self.assertEqual(group.forced, [111, 222])

    def test_term_exit_race_is_reaped(self):
        with patch.object(CAMPAIGN.atexit, "register"):
            group = CAMPAIGN.Children()
        child = MagicMock(pid=111)
        child.poll.return_value = None
        child.wait.return_value = 0
        with patch.object(CAMPAIGN.os, "killpg", side_effect=ProcessLookupError):
            group.stop_group([child])
        child.wait.assert_called_once()
        self.assertEqual(group.forced, [])


class Integrity(unittest.TestCase):
    def setUp(self):
        SCRATCH.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=SCRATCH)
        self.addCleanup(self.temp.cleanup)
        self.db = Path(self.temp.name) / "test.db"
        self.acks = Path(self.temp.name) / "ack.jsonl"
        self.acks.write_text(json.dumps({"id": "row", "title": "title",
            "sha256": hashlib.sha256(b"payload").hexdigest()}) + "\n")
        with sqlite3.connect(self.db) as connection:
            connection.execute("CREATE TABLE memories("
                               "id TEXT, namespace TEXT, title TEXT, content TEXT)")
            connection.execute("INSERT INTO memories VALUES (?, ?, ?, ?)",
                               ("row", "campaign", "title", "payload"))
            connection.execute("INSERT INTO memories VALUES (?, ?, ?, ?)",
                               ("agent", "_agents", "agent", "system row"))

    def test_exact_acknowledged_rows_ignore_system_namespace(self):
        self.assertTrue(CAMPAIGN.reconcile(self.db, self.acks, "campaign")["ok"])

    def test_lost_write_fails(self):
        with sqlite3.connect(self.db) as connection:
            connection.execute("DELETE FROM memories WHERE id=?", ("row",))
        self.assertFalse(CAMPAIGN.reconcile(self.db, self.acks, "campaign")["ok"])

    def test_phantom_write_fails(self):
        with sqlite3.connect(self.db) as connection:
            connection.execute("INSERT INTO memories VALUES (?, ?, ?, ?)",
                               ("phantom", "campaign", "title", "payload"))
        self.assertFalse(CAMPAIGN.reconcile(self.db, self.acks, "campaign")["ok"])

    def test_mutated_payload_fails(self):
        with sqlite3.connect(self.db) as connection:
            connection.execute("UPDATE memories SET content=? WHERE id=?", ("different", "row"))
        self.assertFalse(CAMPAIGN.reconcile(self.db, self.acks, "campaign")["ok"])

    def test_duplicate_ack_fails(self):
        self.acks.write_text(self.acks.read_text() * 2)
        self.assertFalse(CAMPAIGN.reconcile(self.db, self.acks, "campaign")["ok"])

    def test_refused_receipt_must_be_absent(self):
        refused = Path(self.temp.name) / "refused.jsonl"
        refused.write_text(json.dumps({"title": "refused", "status": 503,
                                      "sha256": hashlib.sha256(b"payload").hexdigest()}) + "\n")
        result = CAMPAIGN.reconcile(self.db, self.acks, "campaign", refused)
        self.assertEqual(result["refused_but_present"], 0)
        self.assertEqual(result["refused_checked"], 1)
        self.assertTrue(result["ok"])

    def test_refused_store_that_committed_is_a_finding(self):
        refused = Path(self.temp.name) / "refused.jsonl"
        for status in (503, 504):
            with self.subTest(status=status):
                refused.write_text(json.dumps({"title": "title", "status": status}) + "\n")
                result = CAMPAIGN.reconcile(self.db, self.acks, "campaign", refused)
                self.assertEqual(result["refused_but_present"], 1)
                self.assertFalse(result["ok"])

    def test_phantom_count_and_read_only_query_results_are_explicit(self):
        with sqlite3.connect(self.db) as connection:
            connection.execute("INSERT INTO memories VALUES (?, ?, ?, ?)",
                               ("phantom", "campaign", "extra", "payload"))
        result = CAMPAIGN.reconcile(self.db, self.acks, "campaign")
        self.assertEqual(result["phantom_rows"], 1)
        self.assertEqual(result["queries"][0]["sql"], "PRAGMA integrity_check")
        self.assertEqual(result["queries"][0]["rc"], 0)
        self.assertEqual(result["queries"][1]["rows"], [])

    def test_empty_workload_fails(self):
        self.acks.write_text("")
        with sqlite3.connect(self.db) as connection:
            connection.execute("DELETE FROM memories WHERE namespace=?", ("campaign",))
        self.assertFalse(CAMPAIGN.reconcile(self.db, self.acks, "campaign")["ok"])


class SignedProofs(unittest.TestCase):
    def setUp(self):
        Integrity.setUp(self)
        with sqlite3.connect(self.db) as connection:
            connection.execute("CREATE TABLE signed_events(id TEXT)")

    def run_proofs(self, rows, verifier_rc=0, mcp_response=None):
        with sqlite3.connect(self.db) as connection:
            connection.executemany("INSERT INTO signed_events VALUES (?)", [(str(n),)
                                                                                for n in range(rows)])
        directory = Path(self.temp.name)
        (directory / "acknowledged.jsonl").write_text(self.acks.read_text())
        calls = []

        def run(command, **kwargs):
            calls.append(command)
            if "mcp" in command:
                request = json.loads(kwargs["input"].splitlines()[-1])
                self.assertEqual(request["params"]["arguments"]["link_id"], "row")
                response = mcp_response or {"jsonrpc": "2.0", "id": 2,
                                            "result": {"isError": True, "content": [{"type": "text",
                                            "text": "link_id row is not in the expected form"}]}}
                return subprocess.CompletedProcess(command, 0, json.dumps(response) + "\n", "")
            return subprocess.CompletedProcess(command, verifier_rc, "{}\n", "")

        with patch.object(CAMPAIGN.subprocess, "run", side_effect=run):
            proof = CAMPAIGN.post_run_proofs(Path("fixture-binary"), self.db, {}, directory)
        return proof, calls

    def test_zero_rows_skip_cli_but_keep_negative_control(self):
        proof, calls = self.run_proofs(0)
        self.assertTrue(proof["ok"])
        self.assertEqual(len(calls), 1)
        self.assertEqual(proof["count_rc"], 0)
        self.assertEqual(proof["verifiers"][0]["state"], "SKIP: zero rows")
        self.assertTrue(proof["negative_control"]["observed"])

    def test_rows_require_both_cli_verifiers(self):
        proof, calls = self.run_proofs(1)
        self.assertTrue(proof["ok"])
        self.assertEqual(len(calls), 3)
        self.assertEqual([row["rc"] for row in proof["verifiers"]], [0, 0])

    def test_verifier_error_prevents_passing_proof(self):
        proof, _ = self.run_proofs(1, verifier_rc=1)
        self.assertFalse(proof["ok"])

    def test_missing_negative_control_response_prevents_pass(self):
        proof, _ = self.run_proofs(0, mcp_response={"jsonrpc": "2.0", "id": 1, "result": {}})
        self.assertFalse(proof["ok"])


class Admission(unittest.TestCase):
    def admission(self, runs, load=1, command_rc=0, disk_gib=200, memory_gib=80):
        def command(argv, **_kwargs):
            out = json.dumps(runs) if argv[0] == "gh" else "recorded fixture\n"
            return subprocess.CompletedProcess(argv, command_rc, out, "")

        memory = f"MemAvailable: {memory_gib * 1024**2} kB\n"
        disk = SimpleNamespace(f_bavail=disk_gib * 1024**3, f_frsize=1)
        with patch.object(CAMPAIGN.subprocess, "run", side_effect=command), \
                patch.object(CAMPAIGN.os, "getloadavg", return_value=(load, 1, 1)), \
                patch.object(CAMPAIGN.os, "statvfs", return_value=disk), \
                patch.object(Path, "read_text", return_value=memory):
            return CAMPAIGN.host_admission()

    def test_quiet_host_admits(self):
        self.assertTrue(self.admission([])["admitted"])

    def test_ci_and_coverage_hold(self):
        for workflow in ("CI", "Per-Module Coverage Thresholds"):
            result = self.admission([{"databaseId": 1, "name": workflow,
                                      "workflowName": workflow}])
            self.assertFalse(result["admitted"])

    def test_load_disk_memory_and_query_errors_hold(self):
        for override in ({"load": 8}, {"disk_gib": 99}, {"memory_gib": 39},
                         {"command_rc": 1}):
            with self.subTest(override=override):
                self.assertFalse(self.admission([], **override)["admitted"])

    def test_full_page_holds_in_case_ci_is_hidden(self):
        runs = [{"databaseId": n, "name": "Other", "workflowName": "Other"}
                for n in range(20)]
        self.assertFalse(self.admission(runs)["admitted"])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_known_args()
    unittest.main()
