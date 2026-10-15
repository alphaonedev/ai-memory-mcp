#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Pin the cert-bootstrap gate LEG B evidence behaviour (#7181).

#7181: the required check ``Certified pg+AGE cells`` failed in LEG B of
``scripts/check-bootstrap-cert-gate.sh`` and the gate's evidence
(``bring-up.out``) was lost with the runner workspace. The gate must

* print a bounded, redacted copy of the LEG B evidence into the job log when a
  LEG B row fails (helper ``scripts/cert_gate_evidence.py``),
* mint the witness and recorder keys inside the same hermetic sandbox as every
  other LEG B call (no bare ``"$BIN" identity generate``, output not silenced),
  with EVERY role key directory set explicitly,
* remove every ``mktemp`` work directory on EXIT (``trap``), and
* the workflow must upload the evidence directory with ``if: failure()``.

Stdlib only. Run: ``python3 -I scripts/test/test_cert_gate_evidence_7181.py``
"""
import importlib.util
import io
import re
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GATE = ROOT / "scripts" / "check-bootstrap-cert-gate.sh"
HELPER = ROOT / "scripts" / "cert_gate_evidence.py"
WORKFLOW = ROOT / ".github" / "workflows" / "cert-postgres-age.yml"
TAIL_LINES = 200
ROLE_KEY_DIR_ENVS = (
    "AI_MEMORY_KEY_DIR",
    "AI_MEMORY_WITNESS_KEY_DIR",
    "AI_MEMORY_RECORDER_KEY_DIR",
    "AI_MEMORY_JUDGE_KEY_DIR",
    "AI_MEMORY_STOPPER_KEY_DIR",
)
# Root cause of the #7181 LEG B conviction: the forensic audit sink is a SHARED
# per-user dir (under the state dir); earlier gate runs leave a watermark for
# the same genesis-derived db id, so a fresh bring-up is convicted of
# truncation. Every sandbox wrapper must pin its own sink dirs.
SINK_DIR_ENVS = ("AI_MEMORY_AUDIT_DIR", "AI_MEMORY_LOG_DIR")
PINNED_UPLOAD = re.compile(r"actions/upload-artifact@[0-9a-f]{40}\b")


def _load_helper():
    spec = importlib.util.spec_from_file_location("cert_gate_evidence", HELPER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _leg_b_text() -> str:
    text = GATE.read_text(encoding="utf-8")
    start = text.index("== LEG B")
    return text[start:]


class HelperRedactsAndBounds(unittest.TestCase):
    def test_helper_exists(self):
        self.assertTrue(HELPER.is_file(), "scripts/cert_gate_evidence.py missing")

    def test_redacts_private_key_material_and_tokens(self):
        mod = _load_helper()
        sample = [
            "-----BEGIN " + "PRIVATE KEY-----",
            "private_key: " + "A" * 44,
            "api_" + "token=ghp" + "_abcdefghijklmnopqrstuvwxyz0123456789",
            "db: ./ai-memory.db",
            "CERTIFIED-READY witness role_separation identity_lineage",
        ]
        out = [mod.redact_line(x) for x in sample]
        self.assertNotIn("A" * 16, "\n".join(out))
        self.assertNotIn("ghp" + "_abcdef", "\n".join(out))
        self.assertEqual(out[3], sample[3])
        self.assertEqual(out[4], sample[4])

    def test_tail_is_bounded_with_header(self):
        mod = _load_helper()
        with tempfile.TemporaryDirectory() as td:
            ev = Path(td)
            (ev / "bring-up.out").write_text(
                "".join("line %d\n" % i for i in range(1000)), encoding="utf-8"
            )
            buf = io.StringIO()
            mod.print_evidence(ev, ["bring-up.out", "absent.log"], TAIL_LINES, buf)
            text = buf.getvalue()
        self.assertIn("--- bring-up.out ---", text)
        self.assertIn("line 999", text)
        self.assertNotIn("line 799\n", text)
        self.assertIn("line 800", text)
        self.assertIn("absent.log", text)


class GateScriptPins(unittest.TestCase):
    def test_witness_recorder_generate_is_sandboxed_and_not_silenced(self):
        leg_b = _leg_b_text()
        for agent in ("audit-witness", "governance-recorder"):
            lines = [ln for ln in leg_b.splitlines() if "identity generate" in ln and agent in ln]
            self.assertEqual(len(lines), 1, agent)
            ln = lines[0]
            self.assertTrue(ln.lstrip().startswith("am_b "), "%s not run via am_b: %s" % (agent, ln))
            self.assertNotIn("/dev/null", ln, "%s output still silenced" % agent)
        for ln in leg_b.splitlines():
            if "identity generate" in ln:
                self.assertNotRegex(ln, r'^"\$BIN"', "bare unsandboxed identity generate: " + ln)

    def test_every_role_key_dir_is_explicit_in_each_sandbox_wrapper(self):
        leg_b = _leg_b_text()
        for name in ("am_b", "am_d", "am_e"):
            m = re.search(r"^%s\(\) \{.*?^\}|^%s\(\) \{.*?\}$" % (name, name), leg_b, re.S | re.M)
            self.assertIsNotNone(m, name)
            body = m.group(0)
            for env in ROLE_KEY_DIR_ENVS + SINK_DIR_ENVS:
                self.assertIn(env + "=", body, "%s lacks explicit %s" % (name, env))

    def test_work_dirs_are_cleaned_by_exit_trap(self):
        text = GATE.read_text(encoding="utf-8")
        gate_body = text[text.rindex("EVIDENCE_DIR=") :]
        self.assertRegex(gate_body, r"trap\s+'?\"?\w+.*EXIT")
        self.assertIn("cert_gate_evidence.py", gate_body)

    def test_leg_b_failure_prints_evidence(self):
        text = GATE.read_text(encoding="utf-8")
        self.assertIn("LEGB_FAILED", text)
        self.assertIn("--tail", text)


class WorkflowUploadsEvidence(unittest.TestCase):
    def test_artifact_upload_on_failure_is_pinned(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertRegex(text, PINNED_UPLOAD)
        idx = text.index("cert-bootstrap-evidence")
        block = text[text.rindex("      - name:", 0, text.index("actions/upload-artifact")) :]
        self.assertIn("if: failure()", block)
        self.assertIn(".local-runs/cert-bootstrap-evidence", block)
        self.assertGreater(idx, 0)


if __name__ == "__main__":
    sys.exit(unittest.main(verbosity=2))
