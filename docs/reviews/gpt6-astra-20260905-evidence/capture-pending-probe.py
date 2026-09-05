#!/usr/bin/env python3
"""Reproduce false capture receipts without launching processes or contacting MCP.

Run from the reviewed repository root:
  python3 docs/reviews/gpt6-astra-20260905-evidence/capture-pending-probe.py
Imports the real source adapters; every subprocess.run is mocked locally.
Printed observations are evidence of adapter parsing, not a live governance test.
"""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


def main():
    observations = []
    for vendor in ("openai", "anthropic"):
        path = Path(f"clients/{vendor}-shim-py/ai_memory_{vendor}_shim/_capture.py")
        spec = importlib.util.spec_from_file_location(f"probe_{vendor}", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        for payload in (
            {"status": "pending", "pending_id": "synthetic-pending"},
            {"status": "ask", "reason": "synthetic gate"},
            {"memory_id": "synthetic-persisted", "dedup_hit": False},
        ):
            response = {
                "jsonrpc": "2.0",
                "id": 2,
                "result": {
                    "content": [{"type": "text", "text": json.dumps(payload)}],
                    "isError": False,
                },
            }
            completed = SimpleNamespace(returncode=0, stdout=json.dumps(response))
            warnings = io.StringIO()
            with patch.object(module.subprocess, "run", return_value=completed) as fake:
                with contextlib.redirect_stderr(warnings):
                    success = module.capture_turn(
                        host_session_id="synthetic-astra",
                        host_turn_index=0,
                        role="user",
                        content="synthetic",
                    )
                assert fake.call_count == 1
            observations.append({
                "vendor": vendor,
                "payload": payload,
                "returned_success": success,
                "stderr": warnings.getvalue(),
            })
    print(json.dumps(observations, indent=2))


if __name__ == "__main__":
    main()
