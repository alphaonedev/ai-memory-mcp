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
from unittest.mock import patch

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
                self.assertEqual(CAMPAIGN.evaluate(report)["verdict"], "FINDING")

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

    def test_empty_workload_fails(self):
        self.acks.write_text("")
        with sqlite3.connect(self.db) as connection:
            connection.execute("DELETE FROM memories WHERE namespace=?", ("campaign",))
        self.assertFalse(CAMPAIGN.reconcile(self.db, self.acks, "campaign")["ok"])


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
