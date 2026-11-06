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


STEP_START_RE = re.compile(r"^      - (?:([A-Za-z0-9_-]+):\s*(.*))?$")
STEP_KEY_RE = re.compile(r"^        ([A-Za-z0-9_-]+):\s*(.*)$")
STEP_ENV_RE = re.compile(r"^          ([A-Za-z0-9_]+):\s*(.*)$")
STEP_INDENT = 10


def read_steps(path: Path, job: str) -> List[dict]:
    """Return the steps of `job` as [{"name","id","if","run","uses","env"}] in order.

    `run` is the block scalar text with its 10-space indent removed (a one-line
    `run:` value is returned as is); keys a step does not carry are None.
    """
    steps: List[dict] = []
    in_job = in_steps = False
    run_lines: Optional[List[str]] = None
    in_env = False
    for line in Path(path).read_text().split("\n"):
        job_match = JOB_ID_RE.match(line)
        if job_match:
            in_job = job_match.group(1) == job
            in_steps = False
            run_lines = None
            continue
        if not in_job:
            continue
        if line == "    steps:":
            in_steps = True
            continue
        if not in_steps:
            continue
        if run_lines is not None:
            if not line.strip() or line.startswith(" " * STEP_INDENT):
                run_lines.append(line[STEP_INDENT:])
                continue
            steps[-1]["run"] = "\n".join(run_lines).rstrip("\n") + "\n"
            run_lines = None
        start = STEP_START_RE.match(line)
        if start:
            steps.append({"name": None, "id": None, "if": None, "run": None,
                          "uses": None, "env": {}})
            key, value = start.group(1), start.group(2)
            in_env = False
        else:
            env_match = STEP_ENV_RE.match(line)
            if in_env and env_match and steps:
                steps[-1]["env"][env_match.group(1)] = env_match.group(2).strip()
                continue
            key_match = STEP_KEY_RE.match(line)
            if not key_match or not steps:
                continue
            in_env = key_match.group(1) == "env"
            key, value = key_match.group(1), key_match.group(2)
        if key in ("name", "id", "if", "uses"):
            steps[-1][key] = (value or "").strip()
        elif key == "run":
            if (value or "").strip() in ("|", "|-", ">"):
                run_lines = []
            else:
                steps[-1]["run"] = (value or "").strip()
    if run_lines is not None:
        steps[-1]["run"] = "\n".join(run_lines).rstrip("\n") + "\n"
    return steps
