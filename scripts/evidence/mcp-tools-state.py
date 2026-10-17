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

The record also carries `groups` (tools by family, the token after `memory_`), which is the shape the dashboard
page (infra/cf-dashboard/public/vv.js) renders. Each tool is `validated` unless --classes names it under
`failclosed` or `refining` (a JSON object {"failclosed": {name: note}, "refining": {name: note}}; the older
--failclosed list is still accepted). No percentage is emitted: the page derives it from the counts (#7644).
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(REPO / "infra" / "cf-dashboard"))
import hostscrub  # noqa: E402  (internal hostnames and local paths must never reach the public dashboard, #7518)


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


SURFACE = "MCP (localhost \u00b7 ai-memory mcp --profile full)"
DESC_MAX = 80
TOOL_PREFIX = "memory_"
STATUS_OF = {"validated": "ok", "failclosed": "refusal", "refining": "fail"}


def family_of(name: str) -> str:
    rest = name[len(TOOL_PREFIX):] if name.startswith(TOOL_PREFIX) else name
    return rest.split("_", 1)[0] or name


def short_desc(text) -> str:
    first = str(text or "").strip().split(". ", 1)[0].strip().rstrip(".")
    return first if len(first) <= DESC_MAX else first[:DESC_MAX].rsplit(" ", 1)[0]


def load_classes(args) -> tuple:
    failclosed: dict = {}
    refining: dict = {}
    if args.classes:
        doc = json.loads(args.classes.read_text(encoding="utf-8"))
        failclosed = dict(doc.get("failclosed") or {})
        refining = dict(doc.get("refining") or {})
    if args.failclosed:
        listed = json.loads(args.failclosed.read_text(encoding="utf-8"))
        failclosed.update({n: "" for n in listed} if isinstance(listed, list) else listed)
    return failclosed, refining


def build_groups(tools: list, failclosed: dict, refining: dict) -> list:
    by_name = {t["name"]: t for t in tools if isinstance(t, dict) and t.get("name")}
    families: dict = {}
    for name in sorted(by_name):
        cls = "failclosed" if name in failclosed else "refining" if name in refining else "validated"
        families.setdefault(family_of(name), []).append({
            "name": name,
            "desc": short_desc(by_name[name].get("description")),
            "status": STATUS_OF[cls],
            "cls": cls,
            "note": str(failclosed.get(name) or refining.get(name) or ""),
        })
    return [{"family": f, "tools": families[f]} for f in sorted(families, key=lambda k: (-len(families[k]), k))]


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
    p.add_argument(
        "--classes",
        type=Path,
        help='JSON {"failclosed": {name: note}, "refining": {name: note}}; every other captured tool is validated',
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
    failclosed, refining = load_classes(args)
    unknown = (set(failclosed) | set(refining)) - set(names)
    if unknown:
        print(f"FATAL: {len(unknown)} classified tool(s) are not in the capture", file=sys.stderr)
        return 2
    overlap = set(failclosed) & set(refining)
    if overlap:
        print(f"FATAL: {len(overlap)} tool(s) are both fail-closed and refining", file=sys.stderr)
        return 2
    total = len(names)
    record = {
        "producer_id": "mcp-tools-state",
        "surface": SURFACE,
        "run_id": os.environ.get("EVIDENCE_RUN_ID") or git("rev-parse", "HEAD")[:8] + "-" + str(int(time.time())),
        "source_commit": git("rev-parse", "HEAD"),
        "source_tree_sha": git("rev-parse", "HEAD^{tree}"),
        "lastUpdated": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "total": total,
        "functional": total - len(refining),
        "validated": total - len(failclosed) - len(refining),
        "failclosed": len(failclosed),
        "refining": len(refining),
        "names": names,
        "groups": build_groups(tools, failclosed, refining),
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
    try:
        text = hostscrub.dump_clean(record, indent=2, sort_keys=True)
    except hostscrub.LeakError as exc:
        print(f"FATAL: {exc}", file=sys.stderr)
        return 2
    args.out.write_text(text + "\n", encoding="utf-8")
    print(
        f"[mcp-tools-state] wrote {args.out} total={record['total']} "
        f"validated={record['validated']} failclosed={record['failclosed']}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
