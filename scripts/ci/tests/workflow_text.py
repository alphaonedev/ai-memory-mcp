"""Line-based reader for the job table of a GitHub workflow file (#8240).

Standard library only (no YAML parser): it reads the two-space-indented job
ids under `jobs:` and, per job, the four-space-indented `if:`, `needs:` and
`outputs:` keys. That is all the ci.yml invariant tests need.
"""
import re
from pathlib import Path
from typing import Dict, List, Optional

JOB_ID_RE = re.compile(r"^  ([A-Za-z0-9_-]+):\s*$")
KEY_RE = re.compile(r"^    ([A-Za-z0-9_-]+):\s*(.*)$")
LIST_ITEM_RE = re.compile(r"^      - (\S+)\s*$")
OUTPUT_RE = re.compile(r"^      ([A-Za-z0-9_-]+):\s*(.*)$")


def parse_inline_list(value: str) -> List[str]:
    """Parse `[a, b]` or a bare scalar into a list of ids."""
    value = value.strip()
    if value.startswith("["):
        return [item.strip() for item in value.strip("[]").split(",") if item.strip()]
    return [value] if value else []


def read_jobs(path: Path) -> Dict[str, dict]:
    """Return {job_id: {"if": str|None, "needs": [...], "outputs": {...}}}."""
    jobs: Dict[str, dict] = {}
    in_jobs = False
    current: Optional[str] = None
    block: Optional[str] = None
    for line in Path(path).read_text().split("\n"):
        if line == "jobs:":
            in_jobs = True
            continue
        if not in_jobs:
            continue
        if line and not line.startswith(" "):
            break
        match = JOB_ID_RE.match(line)
        if match:
            current = match.group(1)
            jobs[current] = {"if": None, "needs": [], "outputs": {}}
            block = None
            continue
        if current is None:
            continue
        key = KEY_RE.match(line)
        if key:
            name, value = key.group(1), key.group(2)
            block = name
            if name == "if":
                jobs[current]["if"] = value.strip()
            elif name == "needs":
                jobs[current]["needs"] = parse_inline_list(value)
            continue
        if block == "needs":
            item = LIST_ITEM_RE.match(line)
            if item:
                jobs[current]["needs"].append(item.group(1))
        elif block == "outputs":
            out = OUTPUT_RE.match(line)
            if out:
                jobs[current]["outputs"][out.group(1)] = out.group(2).strip()
    return jobs
