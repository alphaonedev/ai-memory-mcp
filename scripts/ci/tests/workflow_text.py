"""Line-based reader for the job table of a GitHub workflow file (#8240), and the strict reader (#9813).

Standard library only. `read_jobs` and `read_steps` read the two-space-indented job ids under `jobs:` and,
per job, the four-space-indented `if:`, `needs:` and `outputs:` keys. That is all the ci.yml invariant
tests need.

`read_document`, `parse_text` and `read_all_steps` are the strict readers (#9813, PR 9817). The invariant:
they return the value the consumer (GitHub Actions, docker compose) uses, or they raise `WorkflowReadError`
with one reason constant; a file or a form they cannot classify is a refusal, never a pass. A document
passes only when (1) the file check passes (a regular file read through one descriptor, at most
MAX_DOCUMENT_BYTES, valid UTF-8, no byte order mark, not empty or blank-only), (2) every character is LF,
CR LF or printable text (no bare CR, NEL, LS, PS, tab, control, format or non-ASCII space character),
(3) the line prescan finds no form outside the closed grammar (document marker, directive, anchor, alias,
tag, merge key, complex key, quoted key, a blank before a key's `:`, a non-ASCII key, a flow collection
where a block is read), (4) the repository's subset parser (scripts/ci/taint_boundary.py) reads it, and
(5) an independent reader (yaml_line_oracle.py, which splits lines on every YAML line break) reads the same
document, compared key path by key path and scalar by scalar. A refusal names the file, the line (when
known) and the reason; it never quotes document text.
"""
import errno
import importlib.util
import os
import re
import stat
import sys
import unicodedata
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
ORACLE_NAME = "yaml_line_oracle"
ORACLE_PATH = Path(__file__).resolve().parent / "yaml_line_oracle.py"

# The read cap. It equals taint_boundary.MAX_YAML_BYTES, so a file the classifier would refuse for its
# size is refused here with the same limit (pinned by a test).
MAX_DOCUMENT_BYTES = 8 * 1024 * 1024
READ_CHUNK_BYTES = 1024 * 1024
# The open never follows a final symlink and never waits on a FIFO; the checks that follow (fstat) and
# the read act on this one descriptor.
OPEN_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
UTF8_BOM = b"\xef\xbb\xbf"

# File-level refusals.
MISSING = "missing file"
SYMLINK = "a symbolic link (not followed)"
DIRECTORY = "a directory, not a file"
FIFO = "a FIFO, not a regular file"
DEVICE = "a device, not a regular file"
NOT_REGULAR = "not a regular file"
UNREADABLE = "cannot be opened or read"
OVER_CAP = "larger than %d bytes" % MAX_DOCUMENT_BYTES
UTF8 = "not valid UTF-8"
BOM = "byte order mark"
EMPTY = "empty file"
BLANK_ONLY = "no content (blank or comment lines only)"

# Character refusals (each with the line of the first such character).
BARE_CR = "carriage return not followed by a line feed"
LINE_BREAK = "line break other than LF or CR LF (NEL, LS or PS)"
TAB = "tab character"
CONTROL = "control or format character"
NONASCII_SPACE = "non-ASCII space character"

# Grammar refusals: the forms the subset parser does not model, or models differently from the consumer.
DOCUMENT_MARKER = "document marker (`---` or `...`)"
DIRECTIVE = "YAML directive"
QUOTED_KEY = "quoted key"
TRAILING_SPACE_KEY = "blank before the `:` of a key"
NONASCII_KEY = "non-ASCII key"
MERGE_KEY = "merge key `<<`"
ANCHOR = "anchor"
ALIAS = "alias"
TAG = "tag"
COMPLEX_KEY = "complex key `?`"
FLOW_BLOCK = "flow collection where a block is read (`jobs`, a job, or `steps`), or as a block item"
BLOCK_SCALAR = "block scalar header outside the subset"
DUPLICATE_KEY = "duplicate key"
INDENT = "indentation outside the subset (a multi-line plain scalar or a second document)"
NESTING = "nesting deeper than %d levels"
KEY_FORM = "key form outside the subset"
QUOTED_SCALAR = "quoted scalar outside the subset"
FLOW = "flow collection outside the subset"
PLAIN = "plain scalar outside the subset"
OUTSIDE_SUBSET = "form outside the subset"
AMBIGUOUS_SCALAR = "plain scalar whose type differs between YAML 1.1 and 1.2"
KEY_NOT_TEXT = "key that does not read as text"
ORACLE_REFUSED = "form the independent reader does not read"
ORACLE_DIFFERS = "the subset parser and the independent reader disagree"

# Workflow-shape refusals of read_all_steps (jobs and steps are named by ordinal, from 1, never by text).
TOP_NOT_MAPPING = "top level is not a mapping"
JOBS_MISSING = "`jobs` is missing"
JOBS_NOT_MAPPING = "`jobs` is not a mapping"
JOB_NOT_MAPPING = "job %d is not a mapping"
JOB_NO_STEPS = "job %d has neither `steps` nor `uses`"
STEPS_NULL = "job %d: `steps` is null"
STEPS_NOT_LIST = "job %d: `steps` is not a list"
STEP_NOT_MAPPING = "job %d: step %d is not a mapping"
RUN_NULL = "job %d: step %d: `run` is null"
RUN_NOT_TEXT = "job %d: step %d: `run` is not text"

# The subset parser's refusal texts, mapped to a reason by prefix; its text is never passed on, because
# it can quote the document (L2 of PR 9817). The first entry that matches wins.
PARSER_REASONS = (
    ("a quoted scalar that does not close", QUOTED_SCALAR),
    ("empty document", BLANK_ONLY),
    ("content outside the document structure", INDENT),
    ("unexpected indentation", INDENT),
    ("nesting deeper than", None),
    ("tab in indentation", TAB),
    ("duplicate key", DUPLICATE_KEY),
    ("quoted key without", KEY_FORM),
    ("must be followed by a space", KEY_FORM),
    ("key form outside the subset", KEY_FORM),
    ("expected `key: value`", KEY_FORM),
    ("empty or commented key", KEY_FORM),
    ("unsupported escape", QUOTED_SCALAR),
    ("unterminated or multi-line quoted scalar", QUOTED_SCALAR),
    ("text after a quoted scalar", QUOTED_SCALAR),
    ("block scalar", BLOCK_SCALAR),
    ("scalar form outside the subset", PLAIN),
    ("a plain scalar holding", PLAIN),
    ("larger than", OVER_CAP),
    ("flow", FLOW),
    ("trailing comma", FLOW),
    ("empty flow entry", FLOW),
)
PARSER_LINE_RE = re.compile(r": line (\d+): ")
ORACLE_REASONS = {"plain scalar whose type differs between YAML 1.1 and 1.2": AMBIGUOUS_SCALAR,
                  "key that does not read as text": KEY_NOT_TEXT}

# Characters other than LF and printable ASCII; each is classified below, in one linear pass.
SCAN_RE = re.compile(r"[^\n\x20-\x7e]")
LINE_BREAKS = frozenset("\x85  ")
REFUSED_CATEGORIES = {"Cc": CONTROL, "Cf": CONTROL, "Cs": CONTROL, "Co": CONTROL, "Cn": CONTROL,
                      "Zs": NONASCII_SPACE, "Zl": LINE_BREAK, "Zp": LINE_BREAK}
LEAD_REASONS = {"&": ANCHOR, "*": ALIAS, "!": TAG, "?": COMPLEX_KEY, "{": FLOW_BLOCK, "[": FLOW_BLOCK}
VALUE_LEAD_REASONS = {"&": ANCHOR, "*": ALIAS, "!": TAG}
BLOCK_HEADERS = frozenset({"|", "|-", "|+", ">", ">-", ">+"})
FLOW_MERGE_RE = re.compile(r"[\[{,]\s*<<\s*:")
FLOW_NODE_PROPERTY_RE = re.compile(r"[\[{,:]\s*([&*!])")


class WorkflowReadError(Exception):
    """A YAML file the strict reader refuses: the file, the line (when known) and one reason constant.

    The message never quotes document text, so a secret in a refused file cannot reach a log.
    """

    def __init__(self, label: str, line: Optional[int], reason: str) -> None:
        self.label = label
        self.line = line
        self.reason = reason
        where = "%s: line %d" % (label, line) if line is not None else label
        super().__init__("%s: %s" % (where, reason))


def _load(name: str, path: Path, marker: str):
    loaded = sys.modules.get(name)
    if loaded is not None and hasattr(loaded, marker):
        return loaded
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


def load_taint_boundary():
    """The repository's `taint_boundary` module (its subset YAML parser), loaded from its file.

    It is registered once under its own name, because its dataclasses resolve their module through
    `sys.modules`; a copy already imported by name (a test that put scripts/ci on `sys.path`) is reused.
    """
    return _load(TAINT_BOUNDARY_NAME, TAINT_BOUNDARY_PATH, "parse_yaml")


def load_oracle():
    """The independent full-document reader (yaml_line_oracle.py beside this file)."""
    return _load(ORACLE_NAME, ORACLE_PATH, "first_difference")


def _read_checked(target: Path) -> bytes:
    """The bytes of `target`: one descriptor is opened, checked with fstat and read, at most cap + 1 bytes."""
    label = str(target)
    try:
        fd = os.open(target, OPEN_FLAGS)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise WorkflowReadError(label, None, SYMLINK) from None
        if exc.errno in (errno.ENOENT, errno.ENOTDIR):
            raise WorkflowReadError(label, None, MISSING) from None
        raise WorkflowReadError(label, None, UNREADABLE) from None
    try:
        mode = os.fstat(fd).st_mode
        if stat.S_ISDIR(mode):
            raise WorkflowReadError(label, None, DIRECTORY)
        if stat.S_ISFIFO(mode):
            raise WorkflowReadError(label, None, FIFO)
        if stat.S_ISCHR(mode) or stat.S_ISBLK(mode):
            raise WorkflowReadError(label, None, DEVICE)
        if not stat.S_ISREG(mode):
            raise WorkflowReadError(label, None, NOT_REGULAR)
        chunks: List[bytes] = []
        total = 0
        while total <= MAX_DOCUMENT_BYTES:
            try:
                chunk = os.read(fd, READ_CHUNK_BYTES)
            except OSError:
                raise WorkflowReadError(label, None, UNREADABLE) from None
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        if total > MAX_DOCUMENT_BYTES:
            raise WorkflowReadError(label, None, OVER_CAP)
        return b"".join(chunks)
    finally:
        os.close(fd)


def _line_at(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _scan_characters(text: str, label: str) -> None:
    """Refuse every character outside LF, CR LF and printable text, with its line (one linear pass)."""
    for match in SCAN_RE.finditer(text):
        ch = match.group()
        pos = match.start()
        if ch == "\r":
            if text[pos + 1:pos + 2] == "\n":
                continue
            reason = BARE_CR
        elif ch in LINE_BREAKS:
            reason = LINE_BREAK
        elif ch == "\t":
            reason = TAB
        else:
            reason = REFUSED_CATEGORIES.get(unicodedata.category(ch))
            if reason is None:
                continue
        raise WorkflowReadError(label, _line_at(text, pos), reason)


def _quoted_end(body: str) -> int:
    """Index after the quoted scalar that starts `body`, or -1 when it does not close on the line."""
    quote = body[0]
    i = 1
    while i < len(body):
        ch = body[i]
        if quote == '"' and ch == "\\":
            i += 2
            continue
        if ch == quote:
            if quote == "'" and body[i + 1:i + 2] == "'":
                i += 2
                continue
            return i + 1
        i += 1
    return -1


def _key_colon(body: str) -> int:
    """Index of the `:` that ends a plain key (a `:` followed by a blank or the end), else -1."""
    for i, ch in enumerate(body):
        if ch == ":" and (i + 1 == len(body) or body[i + 1] == " "):
            return i
        if ch == "#" and i > 0 and body[i - 1] == " ":
            return -1
    return -1


def _blank_quoted(text: str) -> str:
    """`text` with every quoted span replaced by blanks, so a check sees only the structure."""
    out = []
    i = 0
    while i < len(text):
        ch = text[i]
        if ch in "'\"" and (i == 0 or text[i - 1] in " [{,:"):
            end = _quoted_end(text[i:])
            if end < 0:
                return "".join(out) + " " * (len(text) - i)
            out.append(" " * end)
            i += end
            continue
        if ch == "#" and i > 0 and text[i - 1] == " ":
            return "".join(out)
        out.append(ch)
        i += 1
    return "".join(out)


def _header(value: str) -> str:
    cut = value.find(" #")
    return (value[:cut] if cut >= 0 else value).rstrip(" ")


def _prescan(lines: List[str], label: str) -> None:
    """Refuse the forms the subset parser does not model, line by line (block scalar bodies are skipped)."""
    block_parent: Optional[int] = None
    in_jobs = False
    job_column: Optional[int] = None
    for number, line in enumerate(lines, 1):
        body = line.lstrip(" ")
        indent = len(line) - len(body)
        if block_parent is not None:
            if not body or indent > block_parent:
                continue
            block_parent = None
        if not body or body.startswith("#"):
            continue
        if indent == 0 and (body.startswith("---") or body.startswith("...")):
            raise WorkflowReadError(label, number, DOCUMENT_MARKER)
        if indent == 0 and body.startswith("%"):
            raise WorkflowReadError(label, number, DIRECTIVE)
        column = indent
        dash_column: Optional[int] = None
        while body == "-" or body.startswith("- "):
            dash_column = column
            rest = body[1:].lstrip(" ")
            column += len(body) - len(rest)
            body = rest
        if not body or body.startswith("#"):
            continue
        lead = body[0]
        if lead in LEAD_REASONS:
            raise WorkflowReadError(label, number, LEAD_REASONS[lead])
        if lead in "'\"":
            end = _quoted_end(body)
            if end > 0 and body[end:].lstrip(" ").startswith(":"):
                raise WorkflowReadError(label, number, QUOTED_KEY)
            continue
        if lead in "|>":
            if _header(body) not in BLOCK_HEADERS:
                raise WorkflowReadError(label, number, BLOCK_SCALAR)
            block_parent = dash_column if dash_column is not None else indent
            continue
        colon = _key_colon(body)
        if colon < 0:
            continue
        key = body[:colon]
        if key.startswith("<<"):
            raise WorkflowReadError(label, number, MERGE_KEY)
        if key != key.rstrip(" "):
            raise WorkflowReadError(label, number, TRAILING_SPACE_KEY)
        if not key.isascii():
            raise WorkflowReadError(label, number, NONASCII_KEY)
        if column == 0:
            in_jobs = key == "jobs"
            job_column = None
        elif in_jobs and job_column is None:
            job_column = column
        value = body[colon + 1:].lstrip(" ")
        value_lead = value[:1]
        if value_lead in VALUE_LEAD_REASONS:
            raise WorkflowReadError(label, number, VALUE_LEAD_REASONS[value_lead])
        if value_lead in ("|", ">"):
            if _header(value) not in BLOCK_HEADERS:
                raise WorkflowReadError(label, number, BLOCK_SCALAR)
            block_parent = column
        elif value_lead in ("[", "{"):
            if (column == 0 and key == "jobs") or key == "steps" or (in_jobs and column == job_column):
                raise WorkflowReadError(label, number, FLOW_BLOCK)
            structure = _blank_quoted(value)
            if FLOW_MERGE_RE.search(structure):
                raise WorkflowReadError(label, number, MERGE_KEY)
            prop = FLOW_NODE_PROPERTY_RE.search(structure)
            if prop:
                raise WorkflowReadError(label, number, VALUE_LEAD_REASONS[prop.group(1)])


def _parser_reason(message: str) -> Tuple[Optional[int], str]:
    found = PARSER_LINE_RE.search(message)
    line = int(found.group(1)) if found else None
    for prefix, reason in PARSER_REASONS:
        if prefix in message:
            if reason is None:
                return line, NESTING % load_taint_boundary().MAX_YAML_NESTING
            return line, reason
    return line, OUTSIDE_SUBSET


def _quote_line(text: str, parser_line: Optional[int]) -> Optional[int]:
    """The line a refused quoted scalar opens on, from the independent reader; else `parser_line`."""
    oracle = load_oracle()
    try:
        oracle.read(text)
    except oracle.OracleError as exc:
        if exc.reason == oracle.R_QUOTED:
            return exc.line
    return parser_line


def parse_text(text: str, label: str) -> object:
    """The document of `text` (already decoded) through the closed grammar and both readers.

    Order: size cap, characters, blank-only, the line prescan, the subset parser (taint_boundary), then
    the independent reader (yaml_line_oracle) and a full comparison of the two (every key path and
    scalar, with its type). Any refusal or difference raises WorkflowReadError.

    The subset parser numbers a quoted-scalar refusal in a value from the line after the value (it has
    already stepped past it), so for that reason the line comes from the independent reader, which
    numbers the line the quote opens on; when that reader does not refuse a quoted scalar, the
    parser's line stands.
    """
    if len(text.encode("utf-8", "surrogatepass")) > MAX_DOCUMENT_BYTES:
        raise WorkflowReadError(label, None, OVER_CAP)
    _scan_characters(text, label)
    lines = text.replace("\r\n", "\n").split("\n")
    if not any(line.strip(" ") and not line.lstrip(" ").startswith("#") for line in lines):
        raise WorkflowReadError(label, 1, BLANK_ONLY)
    _prescan(lines, label)
    boundary = load_taint_boundary()
    try:
        document = boundary.parse_yaml(text, "<document>")
    except boundary.YamlError as exc:
        line, reason = _parser_reason(str(exc))
        if reason == QUOTED_SCALAR:
            line = _quote_line(text, line)
        raise WorkflowReadError(label, line, reason) from None
    oracle = load_oracle()
    try:
        independent, key_lines = oracle.read(text)
    except oracle.OracleError as exc:
        raise WorkflowReadError(label, exc.line, ORACLE_REASONS.get(exc.reason, ORACLE_REFUSED)) from None
    difference = oracle.first_difference(document, independent)
    if difference is not None:
        raise WorkflowReadError(label, oracle.line_of(key_lines, difference), ORACLE_DIFFERS)
    return document


def read_document(path: Path) -> object:
    """The parsed YAML document of `path`, or WorkflowReadError with the file, the line and one reason.

    The file is opened once without following a symlink and without waiting on a FIFO; a missing file,
    a directory, a FIFO, a device, any other non-regular file, a file over MAX_DOCUMENT_BYTES, invalid
    UTF-8, a byte order mark, an empty or blank-only file are refused before the text is parsed.
    """
    target = Path(path)
    label = str(target)
    raw = _read_checked(target)
    if not raw:
        raise WorkflowReadError(label, 1, EMPTY)
    if raw.startswith(UTF8_BOM):
        raise WorkflowReadError(label, 1, BOM)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise WorkflowReadError(label, raw.count(b"\n", 0, exc.start) + 1, UTF8) from None
    return parse_text(text, label)


def read_all_steps(path: Path) -> List[Tuple[str, dict]]:
    """Every `(job id, step)` of the workflow at `path`, in file order, from the strict reader.

    A job with `uses` and no `steps` (a reusable-workflow call) has none. Any other shape raises
    WorkflowReadError with one of the shape reasons above: a top level or `jobs` that is not a mapping,
    `jobs` missing, a job that is not a mapping, a job with neither `steps` nor `uses`, `steps` null or not
    a list, a step that is not a mapping, a `run` that is null or not text. Zero jobs (`jobs: {}`) and zero
    steps (`steps: []`) never reach this check: the prescan refuses both as FLOW_BLOCK.
    """
    target = Path(path)
    label = str(target)
    document = read_document(target)
    if not isinstance(document, dict):
        raise WorkflowReadError(label, None, TOP_NOT_MAPPING)
    if "jobs" not in document:
        raise WorkflowReadError(label, None, JOBS_MISSING)
    jobs = document["jobs"]
    if not isinstance(jobs, dict):
        raise WorkflowReadError(label, None, JOBS_NOT_MAPPING)
    found: List[Tuple[str, dict]] = []
    for job_number, (job_id, job) in enumerate(jobs.items(), 1):
        if not isinstance(job, dict):
            raise WorkflowReadError(label, None, JOB_NOT_MAPPING % job_number)
        if "steps" not in job:
            if "uses" in job:
                continue
            raise WorkflowReadError(label, None, JOB_NO_STEPS % job_number)
        steps = job["steps"]
        if steps is None:
            raise WorkflowReadError(label, None, STEPS_NULL % job_number)
        if not isinstance(steps, list):
            raise WorkflowReadError(label, None, STEPS_NOT_LIST % job_number)
        for step_number, step in enumerate(steps, 1):
            if not isinstance(step, dict):
                raise WorkflowReadError(label, None, STEP_NOT_MAPPING % (job_number, step_number))
            if "run" in step:
                if step["run"] is None:
                    raise WorkflowReadError(label, None, RUN_NULL % (job_number, step_number))
                if not isinstance(step["run"], str):
                    raise WorkflowReadError(label, None, RUN_NOT_TEXT % (job_number, step_number))
            found.append((job_id, step))
    return found
