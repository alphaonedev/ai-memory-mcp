#!/usr/bin/env python3
"""Unit test for scripts/check-npm-audit-sdk.py (#7084). No network."""
import contextlib
import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "check-npm-audit-sdk.py"


def run(argv, env=None):
    """Run the gate in a subprocess; returns (rc, stdout)."""
    import subprocess
    proc = subprocess.run([sys.executable, str(SCRIPT)] + argv,
                          capture_output=True, text=True, env=env, check=False)
    return proc.returncode, proc.stdout + proc.stderr


class NpmAuditGate(unittest.TestCase):
    def write(self, text):
        d = tempfile.mkdtemp(dir=os.environ.get("TMPDIR") or None)
        p = Path(d) / "audit.json"
        p.write_text(text, encoding="utf-8")
        return str(p)

    def test_high_finding_exits_1(self):
        rep = {"metadata": {"vulnerabilities": {"info": 0, "low": 0, "moderate": 0,
                                                "high": 1, "critical": 0, "total": 1}},
               "vulnerabilities": {"undici": {"severity": "high", "range": "<6.28.1"}}}
        rc, out = run(["--json-file", self.write(json.dumps(rep))])
        self.assertEqual(rc, 1, out)
        self.assertIn("undici", out)
        self.assertIn("<6.28.1", out)

    def test_clean_exits_0(self):
        rep = {"metadata": {"vulnerabilities": {"info": 0, "low": 1, "moderate": 2,
                                                "high": 0, "critical": 0, "total": 3}},
               "vulnerabilities": {}}
        rc, out = run(["--json-file", self.write(json.dumps(rep))])
        self.assertEqual(rc, 0, out)

    def test_malformed_exits_2(self):
        for bad in ("not json", "{}", '{"metadata": {"vulnerabilities": 5}}'):
            rc, out = run(["--json-file", self.write(bad)])
            self.assertEqual(rc, 2, out)

    def test_missing_file_exits_2(self):
        rc, _ = run(["--json-file", str(ROOT / ".local-runs" / "absent.json")])
        self.assertEqual(rc, 2)

    def test_npm_absent_exits_0_with_notice(self):
        empty = tempfile.mkdtemp(dir=os.environ.get("TMPDIR") or None)
        env = {"PATH": empty}
        rc, out = run([], env=env)
        self.assertEqual(rc, 0, out)
        self.assertIn("::notice::", out)

    def test_omit_dev_passes_flag_to_npm(self):
        spec = importlib.util.spec_from_file_location("gate", str(SCRIPT))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        out = json.dumps({"metadata": {"vulnerabilities": {"high": 0}},
                          "vulnerabilities": {}})
        fake = mock.Mock(stdout=out, stderr="", returncode=0)
        with mock.patch.object(mod.shutil, "which", return_value="/x/npm"), \
                mock.patch.object(mod.subprocess, "run", return_value=fake) as r, \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(mod.main(["--omit-dev"]), 0)
            self.assertIn("--omit=dev", r.call_args[0][0])
            self.assertEqual(mod.main([]), 0)
            self.assertNotIn("--omit=dev", r.call_args[0][0])


if __name__ == "__main__":
    unittest.main()
