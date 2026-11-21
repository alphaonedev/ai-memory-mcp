"""Line-based reader for the job table of a GitHub workflow file (#8240).

Standard library only (no YAML parser): it reads the two-space-indented job
ids under `jobs:` and, per job, the four-space-indented `if:`, `needs:` and
`outputs:` keys. That is all the ci.yml invariant tests need.

#9769: `step_env` / `step_exec_env` are the ONE source of the environment of a
harness that executes the body of a workflow step (by default the check job's
`Run tests (impact-aware)` step): every key of that step's `env:` block, with
each `${{ ... }}` expression replaced by the empty string (what Actions gives an
expression over an unset repository variable or output), so a variable the step
requires can never be missing from one harness while ci.yml supplies it.
"""
import os
import re
from pathlib import Path
from typing import Dict, List, Mapping, Optional

CI_YML = Path(__file__).resolve().parents[3] / ".github" / "workflows" / "ci.yml"
RUN_TESTS_JOB = "check"
RUN_TESTS_STEP = "Run tests (impact-aware)"
EXPRESSION_RE = re.compile(r"\$\{\{.*?\}\}")
# What GitHub Actions substitutes for an expression over an unset variable or output.
UNSET_VALUE = ""
QUOTES = ("'", '"')

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
# `with:` inputs may carry a hyphen (`save-if`, `prefix-key`).
STEP_WITH_RE = re.compile(r"^          ([A-Za-z0-9_-]+):\s*(.*)$")
STEP_INDENT = 10
# One-line step keys kept as text (#9698: the keys that can let a failed step
# pass or bound it in time are read, so a pin can reject them).
STEP_SCALAR_KEYS = ("name", "id", "if", "uses", "continue-on-error", "timeout-minutes")


def read_steps(path: Path, job: str) -> List[dict]:
    """Return the steps of `job` in order as dicts with the keys "name", "id",
    "if", "run", "uses", "continue-on-error", "timeout-minutes", "env", "with".

    `run` is the block scalar text with its 10-space indent removed (a one-line
    `run:` value is returned as is); scalar keys a step does not carry are None;
    `env` and `with` are {key: raw value} maps, empty when absent.
    """
    steps: List[dict] = []
    in_job = in_steps = False
    run_lines: Optional[List[str]] = None
    in_map: Optional[str] = None
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
                          "uses": None, "continue-on-error": None,
                          "timeout-minutes": None, "env": {}, "with": {}})
            key, value = start.group(1), start.group(2)
            in_map = None
        else:
            map_re = STEP_ENV_RE if in_map == "env" else STEP_WITH_RE
            map_match = map_re.match(line) if in_map else None
            if map_match and steps:
                steps[-1][in_map][map_match.group(1)] = map_match.group(2).strip()
                continue
            key_match = STEP_KEY_RE.match(line)
            if not key_match or not steps:
                continue
            in_map = key_match.group(1) if key_match.group(1) in ("env", "with") else None
            key, value = key_match.group(1), key_match.group(2)
        if key in STEP_SCALAR_KEYS:
            steps[-1][key] = (value or "").strip()
        elif key == "run":
            if (value or "").strip() in ("|", "|-", ">"):
                run_lines = []
            else:
                steps[-1]["run"] = (value or "").strip()
    if run_lines is not None:
        steps[-1]["run"] = "\n".join(run_lines).rstrip("\n") + "\n"
    return steps


def env_value(raw: str) -> str:
    """The value a step env entry `raw` has at run time when every expression is unset."""
    value = EXPRESSION_RE.sub(UNSET_VALUE, raw.strip()).strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in QUOTES:
        value = value[1:-1]
    return value


def step_env(path: Path = CI_YML, job: str = RUN_TESTS_JOB, step: str = RUN_TESTS_STEP) -> Dict[str, str]:
    """{key: run-time value} of the `env:` block of step `step` of `job` (exactly one step by name).

    Raises LookupError when the step is absent, named twice or has no env keys,
    so a harness never runs with a silently empty step environment.
    """
    matches = [s for s in read_steps(path, job) if s["name"] == step]
    if len(matches) != 1:
        raise LookupError("%d steps named %r in job %r of %s" % (len(matches), step, job, path))
    if not matches[0]["env"]:
        raise LookupError("step %r of job %r has no env keys" % (step, job))
    return {key: env_value(raw) for key, raw in matches[0]["env"].items()}


def step_exec_env(overrides: Mapping[str, str], base: Optional[Mapping[str, str]] = None,
                  path: Path = CI_YML, job: str = RUN_TESTS_JOB, step: str = RUN_TESTS_STEP) -> Dict[str, str]:
    """The environment a harness runs the step body with.

    `base` (default os.environ) under the step env (so a runner-level value of a
    step key never leaks in), under `overrides` (the harness's own fixture values).
    """
    env = dict(os.environ if base is None else base)
    env.update(step_env(path, job, step))
    env.update(overrides)
    return env
