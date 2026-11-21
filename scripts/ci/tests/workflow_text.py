"""Line-based reader for the job table of a GitHub workflow file (#8240).

Standard library only (no YAML parser): it reads the two-space-indented job
ids under `jobs:` and, per job, the four-space-indented `if:`, `needs:` and
`outputs:` keys. That is all the ci.yml invariant tests need.

`read_document` and `read_all_steps` (#9813) are the strict readers: they parse
the whole file with the repository's own subset parser (scripts/ci/
taint_boundary.py, standard library only) and raise `WorkflowReadError` on a
file they cannot read or a form they do not parse, never returning a partial
or guessed value. A guard that must fail rather than skip reads a workflow
through them.
"""
import importlib.util
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

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


TAINT_BOUNDARY_NAME = "taint_boundary"
TAINT_BOUNDARY_PATH = Path(__file__).resolve().parent.parent / "taint_boundary.py"


class WorkflowReadError(Exception):
    """A workflow file that cannot be read, decoded, parsed or shaped as a workflow (#9813)."""


def load_taint_boundary():
    """The repository's `taint_boundary` module (its subset YAML parser), loaded from its file.

    It is registered once under its own name, because its dataclasses resolve their module through
    `sys.modules`; a copy already imported by name (a test that put scripts/ci on `sys.path`) is reused.
    """
    loaded = sys.modules.get(TAINT_BOUNDARY_NAME)
    if loaded is not None and hasattr(loaded, "parse_yaml"):
        return loaded
    spec = importlib.util.spec_from_file_location(TAINT_BOUNDARY_NAME, TAINT_BOUNDARY_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules[TAINT_BOUNDARY_NAME] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(TAINT_BOUNDARY_NAME, None)
        raise
    return module


def read_document(path: Path) -> object:
    """The parsed YAML document of `path`, or WorkflowReadError naming the file (and the line of a parse refusal)."""
    target = Path(path)
    try:
        raw = target.read_bytes()
    except OSError as exc:
        raise WorkflowReadError("%s: cannot read: %s" % (target, exc.strerror or type(exc).__name__)) from exc
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise WorkflowReadError("%s: not valid UTF-8: %s at byte %d" % (target, exc.reason, exc.start)) from exc
    if not raw:
        raise WorkflowReadError("%s: line 1: empty file" % target)
    boundary = load_taint_boundary()
    try:
        return boundary.parse_yaml(text, str(target))
    except boundary.YamlError as exc:
        raise WorkflowReadError(str(exc)) from exc


def read_all_steps(path: Path) -> List[Tuple[str, dict]]:
    """Every `(job id, step)` of the workflow at `path`, in file order, from the strict reader.

    A job without `steps` (a reusable-workflow call) has none. Any other shape raises WorkflowReadError:
    a top level or `jobs` that is not a mapping, a job that is not a mapping, `steps` that is not a list,
    a step that is not a mapping, a `run` that is not text.
    """
    target = Path(path)
    document = read_document(target)
    if not isinstance(document, dict):
        raise WorkflowReadError("%s: top level is not a mapping" % target)
    jobs = document.get("jobs")
    if not isinstance(jobs, dict):
        raise WorkflowReadError("%s: `jobs` is missing or not a mapping" % target)
    found: List[Tuple[str, dict]] = []
    for job_id, job in jobs.items():
        if not isinstance(job, dict):
            raise WorkflowReadError("%s: job %r is not a mapping" % (target, job_id))
        steps = job.get("steps", [])
        if not isinstance(steps, list):
            raise WorkflowReadError("%s: job %r: `steps` is not a list" % (target, job_id))
        for index, step in enumerate(steps):
            if not isinstance(step, dict):
                raise WorkflowReadError("%s: job %r: step %d is not a mapping" % (target, job_id, index))
            if "run" in step and not isinstance(step["run"], str):
                raise WorkflowReadError("%s: job %r: step %d: `run` is not text" % (target, job_id, index))
            found.append((job_id, step))
    return found
