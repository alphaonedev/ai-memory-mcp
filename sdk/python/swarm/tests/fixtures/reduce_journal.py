# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Reduce a swarm journal to the fields the #3440 replay tests read (#6721).

Usage: python reduce_journal.py JOURNAL_DIR OUT_DIR

Writes ``assessments.json``, ``nhi-audit.json`` and ``calls.jsonl.gz`` into
OUT_DIR. No model prose is kept: ``free_text`` becomes a run of ``x`` of the
same length, store ``content`` keeps only the memory ids it cites, a call
``summary`` keeps only its first memory id, and a title is kept only when the
audit classifies it by its text (a harness prefix or ``mission-summary-<id>``).
"""

from __future__ import annotations

import argparse
import gzip
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from swarm.audit import _MEMORY_ID_RE, HARNESS_TITLE_PREFIXES  # noqa: E402

_RUBRIC = (
    "recall_usefulness",
    "latency_acceptable",
    "failures_encountered",
    "isolation_respected",
    "would_rely_on_it",
)
_ARGS = ("relation", "tier", "scope", "namespace")
_REPORT = ("n_agents", "mission_completion_rate", "mission_partial")


def _assessment(item: dict[str, Any]) -> dict[str, Any]:
    out = {k: item[k] for k in ("agent_id", "assessment_invalid", "error")}
    if not item["assessment_invalid"]:
        out.update({k: item[k] for k in _RUBRIC})
        out["free_text"] = "x" * len(item["free_text"])
    return out


def _call(entry: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {k: entry[k] for k in ("agent_id", "ok", "tool") if k in entry}
    if "origin" in entry:
        out["origin"] = entry["origin"]
    found = _MEMORY_ID_RE.search(str(entry.get("summary") or ""))
    if found:
        out["summary"] = found.group(0)
    raw = entry.get("args")
    if isinstance(raw, dict):
        args = {k: raw[k] for k in _ARGS if k in raw}
        title = str(raw.get("title") or "")
        keep = title.startswith(HARNESS_TITLE_PREFIXES) or title.startswith("mission-summary-")
        if title:
            args["title"] = title if keep else "redacted"
        if "content" in raw:
            args["content"] = " ".join(_MEMORY_ID_RE.findall(str(raw["content"])))
        out["args"] = args
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("journal", type=Path)
    ap.add_argument("out", type=Path)
    a = ap.parse_args()
    a.out.mkdir(parents=True, exist_ok=True)
    stored = json.loads((a.journal / "assessments.json").read_text(encoding="utf-8"))
    (a.out / "assessments.json").write_text(
        json.dumps([_assessment(item) for item in stored], indent=1) + "\n", encoding="utf-8"
    )
    report = json.loads((a.journal / "nhi-audit.json").read_text(encoding="utf-8"))
    (a.out / "nhi-audit.json").write_text(
        json.dumps({k: report[k] for k in _REPORT}, indent=1) + "\n", encoding="utf-8"
    )
    lines = (a.journal / "calls.jsonl").read_text(encoding="utf-8").splitlines()
    calls = [json.dumps(_call(json.loads(line)), sort_keys=True) for line in lines if line.strip()]
    with gzip.GzipFile(a.out / "calls.jsonl.gz", "wb", mtime=0) as handle:
        handle.write(("\n".join(calls) + "\n").encode("utf-8"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
