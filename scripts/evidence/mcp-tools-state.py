#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""mcp-tools-state.py — producer for the MCP-tools inventory figure (#3547).

Refuses to invent a percentage. A named --run-dir must contain a tools/list
capture (`tools-list.json` or `tools_list.json`). The retired dashboard
"95 %" figure had no producer; this script is the only sanctioned writer
of mcp-tools-state.json.

The record carries run_id + source_commit. Binary binding is optional
(--pid / --binary) and required when a live daemon produced the capture.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]


def git(*args: str) -> str:
    return subprocess.check_output(["git", "-C", str(REPO), *args], text=True).strip()


def sha256_of_pid(pid: int) -> str:
    out = subprocess.check_output(
        ["bash", "-c", f"source {HERE / 'lib.sh'} && evidence_sha256_of_pid {pid}"],
        text=True,
    ).strip()
    return out


def sha256_of_file(path: Path) -> str:
    return subprocess.check_output(["shasum", "-a", "256", str(path)], text=True).split()[0]


def load_tools_list(run_dir: Path) -> list:
    for name in ("tools-list.json", "tools_list.json", "tools/list.json"):
        p = run_dir / name
        if p.is_file():
            doc = json.loads(p.read_text(encoding="utf-8"))
            if isinstance(doc, list):
                return doc
            if isinstance(doc, dict):
                return doc.get("tools") or doc.get("result", {}).get("tools") or []
    raise SystemExit(
        f"FATAL: {run_dir} has no tools/list capture "
        "(expected tools-list.json). Refusing to invent a percentage."
    )


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--run-dir",
        type=Path,
        required=True,
        help="named capture directory (must contain tools-list.json)",
    )
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--pid", type=int)
    p.add_argument("--binary", type=Path)
    p.add_argument(
        "--failclosed",
        type=Path,
        help="JSON list of tool names documented as fail-closed on this backend",
    )
    args = p.parse_args()

    if not args.run_dir.is_dir():
        print(f"FATAL: --run-dir is not a directory: {args.run_dir}", file=sys.stderr)
        return 2

    tools = load_tools_list(args.run_dir)
    names = sorted(
        {
            t.get("name")
            for t in tools
            if isinstance(t, dict) and t.get("name")
        }
    )
    failclosed = set()
    if args.failclosed:
        failclosed = set(json.loads(args.failclosed.read_text(encoding="utf-8")))
    validated = [n for n in names if n not in failclosed]
    record = {
        "producer_id": "mcp-tools-state",
        "run_id": os.environ.get("EVIDENCE_RUN_ID") or git("rev-parse", "HEAD")[:8] + "-" + str(int(time.time())),
        "source_commit": git("rev-parse", "HEAD"),
        "source_tree_sha": git("rev-parse", "HEAD^{tree}"),
        "total": len(names),
        "functional": len(names),
        "validated": len(validated),
        "failclosed": len(names) - len(validated),
        "names": names,
        "run_dir": str(args.run_dir),
        "note": "percentage is not emitted; consumers must derive it from total/validated/failclosed of THIS run_id",
    }
    if args.pid is not None:
        digest = sha256_of_pid(args.pid)
        record["daemon_binary_sha256"] = digest
        record["addressed_exe_sha256"] = digest
    elif args.binary is not None:
        digest = sha256_of_file(args.binary)
        record["daemon_binary_sha256"] = digest
        record["addressed_exe_sha256"] = digest
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        f"[mcp-tools-state] wrote {args.out} total={record['total']} "
        f"validated={record['validated']} failclosed={record['failclosed']}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
