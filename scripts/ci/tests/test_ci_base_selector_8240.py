"""The `select` job judges a PR with the selector of its BASE sha (#8240, S2(b)).

decision: base-sha selector over PR-tree selector because a PR must not judge
itself; bootstrap and read failure select ALL (fail closed)

A pull request can edit scripts/ci/impact/select.py or rules.json. If the
select job ran the PR checkout's copy, such a PR could make the
`scripts/ci/**` -> ALL rule a no-op. The workflow therefore materialises the
selector files from the base sha into $RUNNER_TEMP/impact-base/ with an inline
step (the step text lives in ci.yml, so the PR cannot swap the helper) and runs
build_index.py and select.py from that copy against the PR tree's diff.

These tests pull the inline python out of ci.yml, run it against fixture
repositories, then run the materialised selector. No network, no cargo.
"""
import ast
import contextlib
import copy
import hashlib
import importlib
import io
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import types
import unittest
import unittest.mock
from pathlib import Path

import gha_expr
import impact_fixture as fx
import workflow_text

CI_YML = fx.REPO_ROOT / ".github" / "workflows" / "ci.yml"
SELECT_JOB = "select"
GATE_JOB = "ci-gate"
MATERIALISE_STEP = "Materialise the base selector (#8240)"
FALLBACK_STEP = "Select the full matrix (base selector unavailable)"
GATE_MATERIALISE_STEP = "Materialise the base gate (#8240)"
BASE_DIR = "impact-base"
IMPACT_REL = "scripts/ci/impact"
SELECTOR_FILES = ("__init__.py", "common.py", "select.py", "build_index.py",
                  "gate.py", "rules.json")
# The shell ends the heredoc at the FIRST line equal to the terminator: the body holds no such
# line, and anything after the first terminator makes the text not match (sec r10 S3).
HEREDOC_RE = re.compile(r"^python3 -I - <<'PY'\n(?P<body>(?:(?!^PY\n).)*)^PY\n\Z", re.S | re.M)
DECLARED_NON_DOMAIN_OUTPUTS = {"jobs", "all", "crates", "enforce"}
ENFORCE = "true"
WORKFLOW_DIR = fx.REPO_ROOT / ".github" / "workflows"
PR_WORKFLOWS = ("ci.yml", "ci-full.yml", "c8-precheck.yml")
BASE_SHA_MENTION_RE = re.compile(r"base\.sha|BASE_SHA", re.I)
ENV_LINE_RE = re.compile(r"^(?P<indent>\s+)(?P<key>[A-Z][A-Z0-9_]*):\s+(?P<value>\S.*?)\s*$")
EXPRESSION_RE = re.compile(r"^\$\{\{ .+ \}\}$")
SINGLE_BRACE_RE = re.compile(
    r"\$\{(?!\{)\s*(github|env|vars|secrets|inputs|needs|steps|matrix|runner)\.")
LEGACY_SINGLE_BRACE_RE = re.compile(r"\$\{\s")
BASE_EVENT_RE = re.compile(
    r"^\$\{\{ github\.event\.pull_request\.base\.sha( \|\| .+)? \}\}$")
LIVE_BASE_STEP = "Resolve the live base (#8240)"
LIVE_SUMMARY_STEP = "Name the live base in the summary"
RESOLVER_RE = re.compile(r"base_sha\.py")
CONTEXT_SHA_EXPR = "${{ github.sha }}"
HELPER = IMPACT_REL + "/base_sha.py"
BOOTSTRAP_STEP = "Fold job results (bootstrap, PR-tree gate)"
BASE_GATE_STEP = "Fold job results (base gate)"
BRANCH_TIP_STEP = "Fold job results (branch tip gate)"
FAIL_STEP = "Fail the gate (base gate unreadable)"
GATE_SCRIPT = IMPACT_REL + "/gate.py"
FAKE_SHA = "0123456789abcdef0123456789abcdef01234567"


# Strict reader of the workflow document (r7 F1). The repo's workflow helpers are line
# readers and no sibling test imports PyYAML, so this stdlib-only reader parses the block
# YAML ci.yml uses and RAISES on anything else (anchors, tags, multi-line scalars, tabs,
# duplicate keys): a construct it cannot read is a failure, never a skipped line.
class YamlSubsetError(Exception):
    """The document uses YAML this loader does not read; every caller fails closed on it."""


_ESCAPES = {"n": "\n", "t": "\t", "\\": "\\", '"': '"', "/": "/", "0": "\0", "r": "\r", " ": " "}
_INDICATORS = "&*!%@`"
_MAP_ENTRY_RE = re.compile(r":(?: |$)")
_BLOCK_MODS_RE = re.compile(r"^(?:[+-]?[1-9]?|[1-9][+-])$")


def _unquote(text, pos):
    """Read the quoted scalar that starts at text[pos]; return (value, index after it)."""
    quote, out, i = text[pos], [], pos + 1
    while i < len(text):
        ch = text[i]
        if quote == "'" and ch == "'":
            if text[i + 1:i + 2] == "'":
                out.append("'")
                i += 2
                continue
            return "".join(out), i + 1
        if quote == '"' and ch == '"':
            return "".join(out), i + 1
        if quote == '"' and ch == "\\":
            if text[i + 1:i + 2] not in _ESCAPES:
                raise YamlSubsetError("unsupported escape in a double-quoted scalar")
            out.append(_ESCAPES[text[i + 1]])
            i += 2
            continue
        out.append(ch)
        i += 1
    raise YamlSubsetError("unterminated or multi-line quoted scalar")


def _strip_comment(line):
    """Drop a trailing ` # comment` that is outside quotes."""
    quote, i = None, 0
    while i < len(line):
        ch = line[i]
        if quote == "'":
            if ch == "'":
                if line[i + 1:i + 2] == "'":
                    i += 1
                else:
                    quote = None
        elif quote == '"':
            if ch == "\\":
                i += 1
            elif ch == '"':
                quote = None
        elif ch in "'\"" and (i == 0 or line[i - 1] in " \t[{,:"):
            quote = ch
        elif ch == "#" and (i == 0 or line[i - 1] in " \t"):
            return line[:i].rstrip()
        i += 1
    return line.rstrip()


def _parse_flow(text):
    """Parse one single-line flow collection (`[a, b]`, `{k: v}`) or fail closed."""
    size = len(text)

    def ws(pos):
        while pos < size and text[pos] in " \t":
            pos += 1
        return pos

    def scalar(pos, is_key):
        pos = ws(pos)
        if pos >= size:
            raise YamlSubsetError("flow collection ends early")
        if text[pos] in "'\"":
            return _unquote(text, pos)
        if text[pos] in _INDICATORS + "|>":
            raise YamlSubsetError("flow scalar uses an anchor, alias, tag or block indicator")
        start = pos
        while pos < size and text[pos] not in ",]}[{":
            if is_key and text[pos] == ":" and (pos + 1 >= size or text[pos + 1] in " ,]}"):
                break
            pos += 1
        return text[start:pos].strip(), pos

    def node(pos):
        pos = ws(pos)
        if pos >= size:
            raise YamlSubsetError("flow collection ends early")
        if text[pos] == "[":
            items, pos = [], pos + 1
            while True:
                pos = ws(pos)
                if pos < size and text[pos] == "]":
                    return items, pos + 1
                value, pos = node(pos)
                items.append(value)
                pos = ws(pos)
                if pos < size and text[pos] == ",":
                    pos += 1
                elif not (pos < size and text[pos] == "]"):
                    raise YamlSubsetError("flow sequence is not closed")
        if text[pos] == "{":
            result, pos = {}, pos + 1
            while True:
                pos = ws(pos)
                if pos < size and text[pos] == "}":
                    return result, pos + 1
                key, pos = scalar(pos, True)
                pos = ws(pos)
                value = ""
                if pos < size and text[pos] == ":":
                    pos = ws(pos + 1)
                    if pos < size and text[pos] not in ",}":
                        value, pos = node(pos)
                if not key or key in result:
                    raise YamlSubsetError("empty or duplicate flow key")
                result[key] = value
                pos = ws(pos)
                if pos < size and text[pos] == ",":
                    pos += 1
                elif not (pos < size and text[pos] == "}"):
                    raise YamlSubsetError("flow mapping is not closed")
        return scalar(pos, False)

    value, end = node(0)
    if ws(end) != size:
        raise YamlSubsetError("text after a flow collection")
    return value


class _SubsetLoader:
    """Block YAML as ci.yml writes it: mappings, sequences, scalars, flow collections and
    `|` / `>` block scalars. Scalars stay strings. Anchors, aliases, tags, merge keys,
    multi-line plain, quoted or flow scalars, tabs, directives and extra documents raise."""

    def __init__(self, text):
        self.lines = text.split("\n")
        self.i = 0

    def peek(self):
        while self.i < len(self.lines):
            raw = self.lines[self.i].rstrip("\r")
            body = raw.lstrip(" ")
            if raw[:len(raw) - len(body)].count("\t") or body[:1] == "\t":
                raise YamlSubsetError("tab in indentation, line %d" % (self.i + 1))
            if not body.strip() or body.startswith("#"):
                self.i += 1
                continue
            content = _strip_comment(body)
            if content in ("---", "...") or content.startswith(("--- ", "%")):
                raise YamlSubsetError("directive or document marker, line %d" % (self.i + 1))
            return len(raw) - len(body), content
        return None

    @staticmethod
    def is_item(content):
        return content == "-" or content.startswith("- ")

    def parse_block(self, indent):
        content = self.peek()[1]
        return self.parse_seq(indent) if self.is_item(content) else self.parse_map(indent)

    def split_entry(self, content):
        if content[0] in "'\"":
            key, end = _unquote(content, 0)
            tail = content[end:].lstrip(" ")
            if not tail.startswith(":") or (len(tail) > 1 and tail[1] != " "):
                raise YamlSubsetError("quoted scalar is not a mapping key")
            return key, tail[1:].strip()
        if content[0] in "[{?|>" + _INDICATORS:
            raise YamlSubsetError("unsupported mapping key")
        found = _MAP_ENTRY_RE.search(content)
        if found is None or not content[:found.start()].strip():
            raise YamlSubsetError("not a mapping entry (multi-line plain scalar?)")
        return content[:found.start()].rstrip(), content[found.end():].strip()

    def inline(self, rest):
        if rest[0] in "[{":
            return _parse_flow(rest)
        if rest[0] in "'\"":
            value, end = _unquote(rest, 0)
            if rest[end:].strip():
                raise YamlSubsetError("text after a quoted scalar")
            return value
        if rest[0] in _INDICATORS or rest.startswith("<<"):
            raise YamlSubsetError("anchor, alias, tag or merge key")
        if _MAP_ENTRY_RE.search(rest):
            raise YamlSubsetError("a plain scalar holding `: `")
        return rest

    def parse_map(self, indent):
        result = {}
        while True:
            peeked = self.peek()
            if peeked is None or peeked[0] < indent:
                return result
            if peeked[0] > indent:
                raise YamlSubsetError("unexpected indent, line %d" % (self.i + 1))
            if self.is_item(peeked[1]):
                return result
            key, rest = self.split_entry(peeked[1])
            if key in result or key == "<<":
                raise YamlSubsetError("duplicate or merge key %r" % key)
            self.i += 1
            if rest == "":
                nxt = self.peek()
                if nxt is not None and nxt[0] > indent:
                    value = self.parse_block(nxt[0])
                elif nxt is not None and nxt[0] == indent and self.is_item(nxt[1]):
                    value = self.parse_seq(indent)
                else:
                    value = ""
            elif rest[0] in "|>":
                value = self.block_scalar(rest, indent)
            else:
                value = self.inline(rest)
            result[key] = value

    def parse_seq(self, indent):
        items = []
        while True:
            peeked = self.peek()
            if peeked is None or peeked[0] != indent or not self.is_item(peeked[1]):
                if peeked is not None and peeked[0] > indent:
                    raise YamlSubsetError("unexpected indent, line %d" % (self.i + 1))
                return items
            after = peeked[1][1:]
            rest = after.lstrip(" ")
            if rest == "":
                self.i += 1
                nxt = self.peek()
                items.append(self.parse_block(nxt[0]) if nxt is not None and nxt[0] > indent
                             else "")
                continue
            col = indent + 1 + len(after) - len(rest)
            self.lines[self.i] = " " * col + rest
            if self.is_item(rest):
                items.append(self.parse_seq(col))
                continue
            try:
                self.split_entry(rest)
                is_entry = True
            except YamlSubsetError:
                is_entry = False
            if is_entry:
                items.append(self.parse_map(col))
            else:
                self.i += 1
                items.append(self.inline(rest))

    def block_scalar(self, header, key_indent):
        style, mods = header[0], header[1:]
        if not _BLOCK_MODS_RE.match(mods):
            raise YamlSubsetError("unsupported block scalar header %r" % header)
        digits = [c for c in mods if c.isdigit()]
        content_indent = key_indent + int(digits[0]) if digits else None
        lines = []
        while self.i < len(self.lines):
            raw = self.lines[self.i].rstrip("\r")
            if not raw.strip():
                lines.append("")
                self.i += 1
                continue
            indent = len(raw) - len(raw.lstrip(" "))
            if content_indent is None:
                if indent <= key_indent:
                    break
                content_indent = indent
            if indent < content_indent:
                break
            lines.append(raw[content_indent:])
            self.i += 1
        trailing = 0
        while lines and lines[-1] == "":
            lines.pop()
            trailing += 1
        if style == ">":
            folded = ""
            for number, line in enumerate(lines):
                if number and line and lines[number - 1] and not line.startswith(" ") \
                        and not lines[number - 1].startswith(" "):
                    folded += " "
                elif number:
                    folded += "\n"
                folded += line
            text = folded
        else:
            text = "\n".join(lines)
        if not lines:
            return ""
        if "-" in mods:
            return text
        return text + "\n" + ("\n" * trailing if "+" in mods else "")

    def load(self):
        peeked = self.peek()
        if peeked is None:
            return {}
        if peeked[0] != 0:
            raise YamlSubsetError("document does not start at column 0")
        value = self.parse_block(0)
        if self.peek() is not None:
            raise YamlSubsetError("unparsed text, line %d" % (self.i + 1))
        return value


def yaml_subset_load(text):
    """Load `text` with the fail-closed subset reader; raises YamlSubsetError."""
    try:
        return _SubsetLoader(text).load()
    except (IndexError, RecursionError) as exc:
        raise YamlSubsetError("malformed document: %s" % type(exc).__name__)


def derived_env(base, head):
    """Event env under which the materialise step derives exactly `base` (merge_group form).

    `head` is the value of the `github.sha` context: the checked-out commit.
    """
    return {"EVENT_NAME": "merge_group", "HEAD_SHA": "", "MERGE_GROUP_BASE_SHA": base,
            "CONTEXT_SHA": head}


def step_named(job, name):
    """Return the step of `job` called `name`, or fail the test."""
    for step in workflow_text.read_steps(CI_YML, job):
        if step["name"] == name:
            return step
    raise AssertionError("step %r missing in job %s" % (name, job))


def snippet_of(step):
    """Return the inline python source of a `python3 -I - <<'PY'` step."""
    match = HEREDOC_RE.match(step["run"] or "")
    if match is None:
        raise AssertionError("step %r is not an inline python3 -I heredoc" % step["name"])
    return match.group("body")


def run_snippet(source, cwd, env_extra):
    """Run `source` with python -I in `cwd`; return (rc, output lines, summary)."""
    out = cwd.parent / "github_output.txt"
    summary = cwd.parent / "step_summary.md"
    for path in (out, summary):
        path.write_text("")
    env = {"PATH": os.environ["PATH"], "HOME": str(cwd.parent),
           "GITHUB_OUTPUT": str(out), "GITHUB_STEP_SUMMARY": str(summary),
           "RUNNER_TEMP": str(cwd.parent / "runner-temp")}
    env.update(env_extra)
    Path(env["RUNNER_TEMP"]).mkdir(exist_ok=True)
    res = subprocess.run([sys.executable, "-I", "-c", source], cwd=str(cwd), env=env,
                         capture_output=True, text=True, timeout=120)
    lines = dict(item.split("=", 1) for item in out.read_text().split("\n") if "=" in item)
    return res.returncode, lines, summary.read_text(), res


class BaseCase(unittest.TestCase):
    """A fixture repo whose base commit carries the real selector files."""

    def setUp(self):
        scratch = fx.make_scratch()
        self.addCleanup(scratch.cleanup)
        self.tmp = Path(scratch.name)
        self.repo = self.tmp / "repo"
        self.base = fx.init_repo(self.repo)
        self.dest = self.tmp / "runner-temp" / BASE_DIR

    def commit_selector(self, skip=()):
        """Commit the real selector files onto the fixture and return the sha."""
        files = {}
        for name in SELECTOR_FILES:
            if name not in skip:
                files["%s/%s" % (IMPACT_REL, name)] = (fx.IMPACT_DIR / name).read_text()
        return fx.commit_change(self.repo, files)

    def materialise(self, base, files=" ".join(SELECTOR_FILES), source=None):
        step = step_named(SELECT_JOB, MATERIALISE_STEP)
        head = fx.git(self.repo, "rev-parse", "HEAD")
        return run_snippet(source or snippet_of(step), self.repo,
                           dict(derived_env(base, head), IMPACT_FILES=files))


class WorkflowShape(unittest.TestCase):
    def test_select_job_materialises_before_it_builds_and_selects(self):
        names = [s["name"] for s in workflow_text.read_steps(CI_YML, SELECT_JOB)]
        self.assertIn(MATERIALISE_STEP, names)
        self.assertLess(names.index(MATERIALISE_STEP), names.index("Build impact index"))
        self.assertLess(names.index("Build impact index"), names.index("Select jobs"))

    def test_no_select_job_step_runs_the_pr_tree_selector(self):
        for step in workflow_text.read_steps(CI_YML, SELECT_JOB):
            run = step["run"] or ""
            with self.subTest(step=step["name"]):
                self.assertNotRegex(run, r"scripts/ci/impact/(select|build_index)\.py")

    def test_build_and_select_run_from_the_base_copy(self):
        for name, script in (("Build impact index", "build_index.py"),
                             ("Select jobs", "select.py")):
            step = step_named(SELECT_JOB, name)
            with self.subTest(step=name):
                self.assertIn('"$RUNNER_TEMP/%s/impact/%s"' % (BASE_DIR, script), step["run"])
                self.assertIn("steps.base.outputs.ok == 'true'", step["if"])

    def test_materialise_step_lists_the_selector_files(self):
        step = step_named(SELECT_JOB, MATERIALISE_STEP)
        listed = step["env"]["IMPACT_FILES"].split()
        self.assertEqual(sorted(listed), sorted(SELECTOR_FILES))
        self.assertEqual(step["id"], "base")

    def test_fallback_step_runs_when_the_base_copy_is_not_ok(self):
        step = step_named(SELECT_JOB, FALLBACK_STEP)
        self.assertEqual(step["if"],
                         "${{ !cancelled() && steps.base.outputs.ok != 'true' }}")

    def test_select_outputs_fall_back_to_the_full_matrix_step(self):
        outputs = workflow_text.read_jobs(CI_YML)[SELECT_JOB]["outputs"]
        for key, value in outputs.items():
            if key == "enforce":
                continue
            with self.subTest(output=key):
                self.assertIn("steps.select.outputs.%s" % key, value)
                self.assertIn("steps.fallback.outputs.%s" % key, value)

    def test_gate_job_runs_the_base_gate_when_available(self):
        materialise = step_named(GATE_JOB, GATE_MATERIALISE_STEP)
        self.assertEqual(materialise["id"], "base")
        runs = [s for s in workflow_text.read_steps(CI_YML, GATE_JOB)
                if s["run"] and "gate.py" in s["run"] and "<<'PY'" not in s["run"]
                and s["name"] != BRANCH_TIP_STEP]
        self.assertEqual(len(runs), 2)
        base_run = [s for s in runs if BASE_DIR in s["run"]]
        pr_run = [s for s in runs if BASE_DIR not in s["run"]]
        self.assertEqual(len(base_run), 1)
        self.assertEqual(len(pr_run), 1)
        self.assertIn("steps.base.outputs.ok == 'true'", base_run[0]["if"])
        self.assertEqual(pr_run[0]["if"],
                         "${{ !cancelled() && (github.event_name == 'pull_request' || "
                         "github.event_name == 'merge_group') && "
                         "steps.base.outputs.ok != 'true' "
                         "&& steps.base.outputs.bootstrap == 'true' }}")
        self.assertTrue(base_run[0]["if"].startswith("${{ !cancelled() &&"))

    def test_the_two_materialise_steps_share_one_source(self):
        select_src = snippet_of(step_named(SELECT_JOB, MATERIALISE_STEP))
        gate_src = snippet_of(step_named(GATE_JOB, GATE_MATERIALISE_STEP))
        self.assertEqual(select_src, gate_src)


class WorkflowExpressions(unittest.TestCase):
    """S7: a one-brace `${ ... }` is literal text, so the selector never saw its base sha."""

    def test_every_base_sha_env_value_is_a_well_formed_expression(self):
        for name in PR_WORKFLOWS:
            path = WORKFLOW_DIR / name
            for number, line in enumerate(path.read_text().split("\n"), 1):
                if line.lstrip().startswith("#"):
                    continue
                match = ENV_LINE_RE.match(line)
                if match is None or not BASE_SHA_MENTION_RE.search(match.group("value")):
                    continue
                with self.subTest(file=name, line=number):
                    self.assertRegex(
                        match.group("value"), EXPRESSION_RE,
                        "%s:%d %s is not a well-formed ${{ ... }} expression"
                        % (name, number, match.group("key")))

    def test_no_single_brace_expression_in_the_workflow_files_the_pr_touches(self):
        for name in PR_WORKFLOWS:
            path = WORKFLOW_DIR / name
            for number, line in enumerate(path.read_text().split("\n"), 1):
                with self.subTest(file=name, line=number):
                    self.assertIsNone(SINGLE_BRACE_RE.search(line),
                                      "%s:%d has a single-brace ${ expression" % (name, number))
                    self.assertIsNone(LEGACY_SINGLE_BRACE_RE.search(line),
                                      "%s:%d has a single-brace ${ expression" % (name, number))

    def test_both_materialise_steps_take_the_checked_out_sha_from_the_context(self):
        for job, step_name in ((SELECT_JOB, MATERIALISE_STEP),
                               (GATE_JOB, GATE_MATERIALISE_STEP)):
            with self.subTest(job=job):
                env = step_named(job, step_name)["env"]
                self.assertEqual(env["CONTEXT_SHA"], CONTEXT_SHA_EXPR)
                self.assertNotIn("BASE_SHA", env)

    def test_the_no_space_single_brace_form_is_flagged(self):
        for text in ("X: ${github.event.pull_request.head.sha || github.sha}",
                     "X: ${ github.event.before }", "X: ${env.FOO}",
                     "X: ${secrets.TOKEN}", "X: ${steps.base.outputs.ok}"):
            with self.subTest(text=text):
                self.assertTrue(SINGLE_BRACE_RE.search(text) or
                                LEGACY_SINGLE_BRACE_RE.search(text))
        for text in ("echo ${HOME}", 'echo "${GITHUB_ENV}"', "x=${y:-1}",
                     "X: ${{ github.sha }}"):
            with self.subTest(text=text):
                self.assertIsNone(SINGLE_BRACE_RE.search(text))
                self.assertIsNone(LEGACY_SINGLE_BRACE_RE.search(text))


class GateBaseRead(BaseCase):
    """S8: the PR-tree gate runs only when the base has no gate.py; any other read failure fails.

    decision: fail the gate on a non-bootstrap base read failure over falling
    back to the PR tree because a fallback the PR can trigger is self-judging;
    the select job already fails safe to the full matrix, the gate must fail
    closed
    """

    def gate_materialise(self, base, path=None):
        step = step_named(GATE_JOB, GATE_MATERIALISE_STEP)
        head = fx.git(self.repo, "rev-parse", "HEAD")
        env = dict(derived_env(base, head), IMPACT_FILES=step["env"]["IMPACT_FILES"])
        if path is not None:
            env["PATH"] = path
        return run_snippet(snippet_of(step), self.repo, env)

    def plan(self, lines):
        """Return the names of the gate steps whose `if:` holds after the materialise step."""
        context = {"github": {"event_name": "pull_request"},
                   "steps": {"base": {"outputs": lines}}}
        ran = []
        for step in workflow_text.read_steps(CI_YML, GATE_JOB):
            if step["uses"] or step["name"] == GATE_MATERIALISE_STEP:
                continue
            if step["if"] is None or gha_expr.evaluate_job_if(step["if"], context):
                ran.append(step["name"])
        return ran

    def failing_git(self, subcommand):
        """Return a PATH whose `git <subcommand>` exits 128 and whose other calls pass through."""
        real = shutil.which("git")
        wrapper_dir = self.tmp / "wrapbin"
        wrapper_dir.mkdir()
        wrapper = wrapper_dir / "git"
        wrapper.write_text("#!%s\nimport os\nimport sys\nif %r in sys.argv[1:3]:\n"
                           "    sys.exit(128)\nos.execv(%r, [%r] + sys.argv[1:])\n"
                           % (sys.executable, subcommand, real, real))
        wrapper.chmod(wrapper.stat().st_mode | stat.S_IXUSR)
        return str(wrapper_dir) + os.pathsep + os.environ["PATH"]

    def run_fail_step(self, reason):
        step = step_named(GATE_JOB, FAIL_STEP)
        summary = self.tmp / "fail_summary.md"
        summary.write_text("")
        env = {"PATH": os.environ["PATH"], "IMPACT_REASON": reason,
               "GITHUB_STEP_SUMMARY": str(summary)}
        res = subprocess.run(["bash", "-e", "-c", step["run"]], cwd=str(self.repo), env=env,
                             capture_output=True, text=True, timeout=60)
        return res.returncode, summary.read_text()

    def assert_fails_closed(self, lines, summary):
        self.assertEqual(lines.get("ok"), "false", summary)
        self.assertNotEqual(lines.get("bootstrap"), "true", summary)
        ran = self.plan(lines)
        self.assertEqual(ran, [FAIL_STEP])
        self.assertNotIn(BOOTSTRAP_STEP, ran)
        code, text = self.run_fail_step(lines.get("reason", ""))
        self.assertNotEqual(code, 0)
        self.assertIn(lines["reason"], text)
        self.assertNotIn("full matrix", text)

    def test_a_base_without_gate_py_is_the_bootstrap_and_runs_the_pr_tree_gate(self):
        rc, lines, summary, res = self.gate_materialise(self.base)
        self.assertEqual(lines.get("ok"), "false", summary)
        self.assertEqual(lines.get("bootstrap"), "true", summary)
        self.assertEqual(self.plan(lines), [BOOTSTRAP_STEP])
        self.assertIn("bootstrap", summary)
        self.assertNotIn("full matrix", summary)
        run = step_named(GATE_JOB, BOOTSTRAP_STEP)["run"]
        self.assertIn(GATE_SCRIPT, run)
        self.assertNotIn(BASE_DIR, run)

    def test_a_base_with_other_files_but_no_gate_py_is_still_the_bootstrap(self):
        base = self.commit_selector(skip=("gate.py",))
        rc, lines, summary, res = self.gate_materialise(base)
        self.assertEqual(lines.get("bootstrap"), "true", summary)
        self.assertEqual(self.plan(lines), [BOOTSTRAP_STEP])

    def test_a_readable_base_runs_only_the_base_gate(self):
        base = self.commit_selector()
        rc, lines, summary, res = self.gate_materialise(base)
        self.assertEqual(lines.get("ok"), "true", summary)
        self.assertEqual(self.plan(lines), [BASE_GATE_STEP])

    def test_a_failing_git_show_of_a_present_gate_py_fails_the_gate(self):
        base = self.commit_selector()
        rc, lines, summary, res = self.gate_materialise(base, self.failing_git("show"))
        self.assert_fails_closed(lines, summary)

    def test_a_failing_ls_tree_fails_the_gate(self):
        base = self.commit_selector()
        rc, lines, summary, res = self.gate_materialise(base, self.failing_git("ls-tree"))
        self.assert_fails_closed(lines, summary)

    def test_a_missing_non_gate_file_with_gate_py_present_fails_the_gate(self):
        base = self.commit_selector(skip=("rules.json",))
        rc, lines, summary, res = self.gate_materialise(base)
        self.assert_fails_closed(lines, summary)

    def test_an_unfetchable_base_sha_fails_the_gate(self):
        self.commit_selector()
        rc, lines, summary, res = self.gate_materialise(FAKE_SHA)
        self.assert_fails_closed(lines, summary)

    def test_an_invalid_base_sha_fails_the_gate(self):
        self.commit_selector()
        for bad in ("", "--upload-pack=x", "main", FAKE_SHA.upper()):
            with self.subTest(sha=bad):
                rc, lines, summary, res = self.gate_materialise(bad)
                self.assert_fails_closed(lines, summary)
                self.assertEqual(lines["reason"], "base-sha-invalid")

    def test_the_pr_tree_gate_step_runs_only_on_the_bootstrap_output(self):
        step = step_named(GATE_JOB, BOOTSTRAP_STEP)
        self.assertIn("steps.base.outputs.bootstrap == 'true'", step["if"])
        self.assertTrue(step["if"].startswith("${{ !cancelled() &&"))


class BaseSelectorIgnoresPrHelpers(BaseCase):
    """S9: a base selector must not import helpers from the PR tree it is judging."""

    MARKER = "PR_TREE_HELPER_IMPORTED"

    def argv_of(self, step_name, env):
        """Return the step's command exactly as ci.yml writes it, variables expanded."""
        run = step_named(SELECT_JOB, step_name)["run"].replace("\\\n", " ")
        words = shlex.split(re.sub(r"\$(\w+)", lambda m: env[m.group(1)], run))
        self.assertEqual(words[0], "python3")
        words[0] = sys.executable
        self.assertIn("-I", words[1:3], "%s must run with python3 -I" % step_name)
        return words

    def env_of(self, step_name, base_env, step_env):
        """Return the process env the runner builds: the step's REAL `env:` block applied.

        Literal values are used as written; `${{ ... }}` values come from `step_env`
        (the test's stand-in for the expression context, keyed by variable name).
        """
        env = dict(base_env)
        for key, value in step_named(SELECT_JOB, step_name)["env"].items():
            self.assertFalse(key.upper().startswith("PYTHON"),
                             "step %r sets %s, which redirects imports" % (step_name, key))
            env[key] = step_env[key] if value.startswith("${{") else value
        return env

    def test_the_base_selector_never_imports_a_pr_tree_helper(self):
        base = self.commit_selector()
        sentinel = ((fx.IMPACT_DIR / "common.py").read_text()
                    + "\nopen(%r, 'w').write('imported')\n" % self.MARKER)
        head = fx.commit_change(self.repo, {"%s/common.py" % IMPACT_REL: sentinel,
                                            "crates/core/src/lib.rs": "// changed\n"})
        rc, lines, summary, res = self.materialise(base)
        self.assertEqual(lines.get("ok"), "true", summary)
        marker = self.repo / self.MARKER
        env = {"PATH": os.environ["PATH"], "HOME": str(self.tmp)}
        pr_run = subprocess.run(
            [sys.executable, "-I", str(self.repo / IMPACT_REL / "select.py"),
             "--db", str(self.tmp / "none.db"), "--repo", ".", "--base", base, "--head", head],
            cwd=str(self.repo), env=env, capture_output=True, text=True, timeout=120)
        self.assertTrue(marker.exists(), "control: the PR-tree helper was not imported\n"
                        + pr_run.stderr)
        marker.unlink()
        out = self.tmp / "selected.txt"
        out.write_text("")
        metadata = self.tmp / "metadata.json"
        metadata.write_text(json.dumps(fx.make_metadata(self.repo)))
        step_env = {"RUNNER_TEMP": str(self.tmp / "runner-temp"), "BASE_SHA": base,
                    "HEAD_SHA": head, "EVENT": "pull_request", "BASE_REF": "main",
                    "ENFORCE": ENFORCE, "GITHUB_OUTPUT": str(out)}
        build = self.argv_of("Build impact index", step_env) + ["--metadata-file", str(metadata)]
        select = self.argv_of("Select jobs", step_env)
        for name, argv in (("Build impact index", build), ("Select jobs", select)):
            done = subprocess.run(argv, cwd=str(self.repo), capture_output=True,
                                  env=self.env_of(name, env, step_env),
                                  text=True, timeout=120)
            self.assertEqual(done.returncode, 0, done.stderr)
        self.assertFalse(marker.exists(), "the base selector imported a PR-tree helper")
        selected = dict(item.split("=", 1) for item in out.read_text().split("\n") if "=" in item)
        self.assertEqual(selected["all"], "true")


class BaseSelectorBeatsPrSelector(BaseCase):
    """The self-judging PR: its select.py selects nothing, the base copy does not."""

    STUB = ("import sys\n"
            "out = sys.argv[sys.argv.index('--github-output') + 1]\n"
            "open(out, 'a').write('all=false\\njobs=\\ncrates=\\nrust=false\\n"
            "cells=false\\nactionlint=false\\n')\n")

    def run_selector(self, script, head):
        metadata = self.tmp / "metadata.json"
        metadata.write_text(json.dumps(fx.make_metadata(self.repo)))
        db = self.tmp / ("impact-%s.db" % script.parent.name)
        env = {"PATH": os.environ["PATH"], "HOME": str(self.tmp)}
        out = self.tmp / ("out-%s.txt" % script.parent.name)
        out.write_text("")
        if (script.parent / "build_index.py").exists():
            subprocess.run([sys.executable, "-I", str(script.parent / "build_index.py"),
                            "--repo", str(self.repo), "--db", str(db),
                            "--metadata-file", str(metadata)],
                           cwd=str(self.repo), env=env, check=True,
                           capture_output=True, text=True, timeout=120)
        subprocess.run([sys.executable, "-I", str(script), "--db", str(db),
                        "--repo", str(self.repo), "--base", self.base, "--head", head,
                        "--event", "pull_request", "--enforce", ENFORCE,
                        "--github-output", str(out)],
                       cwd=str(self.repo), env=env, check=True,
                       capture_output=True, text=True, timeout=120)
        return dict(item.split("=", 1) for item in out.read_text().split("\n") if "=" in item)

    def test_pr_rewriting_select_py_cannot_narrow_the_selection(self):
        base = self.commit_selector()
        self.base = base
        head = fx.commit_change(self.repo, {
            "%s/select.py" % IMPACT_REL: self.STUB,
            "crates/core/src/lib.rs": "// changed\n"})
        rc, lines, summary, res = self.materialise(base)
        self.assertEqual(rc, 0, res.stderr)
        self.assertEqual(lines.get("ok"), "true", summary)
        pr_tree = self.run_selector(self.repo / IMPACT_REL / "select.py", head)
        self.assertEqual(pr_tree["all"], "false")
        self.assertEqual(pr_tree["rust"], "false")
        from_base = self.run_selector(self.dest / "impact" / "select.py", head)
        self.assertEqual(from_base["all"], "true")
        for domain in ("rust", "cells", "actionlint"):
            with self.subTest(domain=domain):
                self.assertEqual(from_base[domain], "true")

    def test_materialised_files_equal_the_base_blobs_not_the_pr_files(self):
        base = self.commit_selector()
        fx.commit_change(self.repo, {"%s/select.py" % IMPACT_REL: self.STUB})
        rc, lines, summary, res = self.materialise(base)
        self.assertEqual(lines.get("ok"), "true", summary)
        self.assertEqual((self.dest / "impact" / "select.py").read_text(),
                         (fx.IMPACT_DIR / "select.py").read_text())
        for name in SELECTOR_FILES:
            with self.subTest(file=name):
                self.assertTrue((self.dest / "impact" / name).is_file())


class FailClosed(BaseCase):
    def assert_closed(self, base, files=" ".join(SELECTOR_FILES), source=None):
        rc, lines, summary, res = self.materialise(base, files, source)
        self.assertEqual(rc, 0, res.stderr)
        self.assertEqual(lines.get("ok"), "false", summary)
        self.assertIn("impact: base files unavailable", summary)
        self.assertNotIn("full matrix", summary)
        self.assertFalse(self.dest.exists(), "partial base copy left behind")
        return summary

    def test_bootstrap_base_without_the_files_selects_all(self):
        summary = self.assert_closed(self.base)
        self.assertIn("base-file-missing:__init__.py", summary)

    def test_one_missing_file_selects_all_and_leaves_no_copy(self):
        base = self.commit_selector(skip=("gate.py",))
        summary = self.assert_closed(base)
        self.assertIn("base-file-missing:gate.py", summary)

    def test_empty_file_list_selects_all(self):
        base = self.commit_selector()
        rc, lines, summary, res = self.materialise(base, files="")
        self.assertEqual(lines.get("ok"), "false", summary)
        self.assertIn("no-files-listed", summary)

    def test_unknown_sha_selects_all(self):
        self.assert_closed(FAKE_SHA)

    def test_malformed_sha_selects_all(self):
        for bad in ("", "--upload-pack=x", "main", FAKE_SHA.upper(), FAKE_SHA + "0"):
            with self.subTest(sha=bad):
                summary = self.assert_closed(bad)
                self.assertIn("base-sha-invalid", summary)

    def test_symlinked_base_file_is_refused(self):
        self.commit_selector()
        target = self.repo / IMPACT_REL / "select.py"
        target.unlink()
        target.symlink_to("common.py")
        fx.git(self.repo, "add", "-A")
        fx.git(self.repo, "commit", "-q", "-m", "link")
        base = fx.git(self.repo, "rev-parse", "HEAD")
        summary = self.assert_closed(base)
        self.assertIn("base-file-not-regular:select.py", summary)

    def test_symlink_at_the_destination_is_refused(self):
        base = self.commit_selector()
        self.dest.parent.mkdir(parents=True, exist_ok=True)
        elsewhere = self.tmp / "elsewhere"
        elsewhere.mkdir()
        self.dest.symlink_to(elsewhere)
        rc, lines, summary, res = self.materialise(base)
        self.assertEqual(lines.get("ok"), "false", summary)
        self.assertIn("dest-unsafe", summary)
        self.assertEqual(list(elsewhere.iterdir()), [], "wrote through the symlink")

    def test_dangling_symlink_at_the_destination_is_refused(self):
        base = self.commit_selector()
        self.dest.parent.mkdir(parents=True, exist_ok=True)
        self.dest.symlink_to(self.tmp / "does-not-exist")
        rc, lines, summary, res = self.materialise(base)
        self.assertEqual(lines.get("ok"), "false", summary)
        self.assertIn("dest-unsafe", summary)

    def test_write_failure_midway_removes_the_partial_copy(self):
        base = self.commit_selector()
        source = snippet_of(step_named(SELECT_JOB, MATERIALISE_STEP))
        namespace = {"__name__": "snippet"}
        exec(compile(source, "materialise", "exec"), namespace)
        calls = {"n": 0}
        real = Path.write_bytes

        def flaky(path, data):
            calls["n"] += 1
            if calls["n"] == 3:
                raise OSError(28, "No space left on device")
            return real(path, data)

        env = dict(derived_env(base, fx.git(self.repo, "rev-parse", "HEAD")),
                   IMPACT_FILES=" ".join(SELECTOR_FILES),
                   RUNNER_TEMP=str(self.tmp / "runner-temp"),
                   GITHUB_OUTPUT=str(self.tmp / "go.txt"),
                   GITHUB_STEP_SUMMARY=str(self.tmp / "gs.md"))
        (self.tmp / "runner-temp").mkdir()
        cwd = os.getcwd()
        os.chdir(str(self.repo))
        try:
            with unittest.mock.patch.dict(os.environ, env), \
                    unittest.mock.patch.object(Path, "write_bytes", flaky), \
                    contextlib.redirect_stdout(io.StringIO()):
                namespace["main"]()
        finally:
            os.chdir(cwd)
        self.assertFalse(self.dest.exists(), "partial copy survived ENOSPC")
        self.assertIn("ok=false", (self.tmp / "go.txt").read_text())
        self.assertIn("write-failed", (self.tmp / "gs.md").read_text())

    def test_summary_names_no_environment_value(self):
        summary = self.assert_closed("--upload-pack=secret-value-xyz")
        self.assertNotIn("secret-value-xyz", summary)


class FallbackStep(unittest.TestCase):
    """The `fallback` step is what the select job reports when the copy is unusable."""

    def test_fallback_selects_every_declared_domain(self):
        scratch = fx.make_scratch()
        self.addCleanup(scratch.cleanup)
        cwd = Path(scratch.name) / "work"
        cwd.mkdir()
        step = step_named(SELECT_JOB, FALLBACK_STEP)
        rc, lines, summary, res = run_snippet(snippet_of(step), cwd, {})
        self.assertEqual(rc, 0, res.stderr)
        self.assertEqual(step["id"], "fallback")
        self.assertEqual(lines["all"], "true")
        self.assertIn("selecting the full matrix", summary)
        outputs =workflow_text.read_jobs(CI_YML)[SELECT_JOB]["outputs"]
        domains = set(outputs) - DECLARED_NON_DOMAIN_OUTPUTS
        self.assertEqual(domains, {"rust", "cells", "actionlint"})
        for domain in domains:
            with self.subTest(domain=domain):
                self.assertEqual(lines[domain], "true")
        self.assertNotIn("false", lines.values())


class LiveBase(BaseCase):
    """R3-F10: the base is the live one, never the frozen pull_request.base.sha.

    decision: the live base is the first parent of the pull_request merge ref
    and merge_group.base_sha over pull_request.base.sha because base.sha is
    frozen at PR-open time and github.sha on merge_group contains the PR
    """

    def build(self):
        """main: c0 -> c1 (later base); pr: c0 -> p1; merge M = c1 + p1 on HEAD."""
        c0 = self.base
        git = lambda *a: fx.git(self.repo, *a)
        git("checkout", "-q", "-b", "pr")
        p1 = fx.commit_change(self.repo, {"pr.txt": "pr\n"})
        git("checkout", "-q", "main")
        c1 = fx.commit_change(self.repo, {"later.txt": "later\n"})
        git("checkout", "-q", "-b", "merge-ref")
        git("merge", "-q", "--no-ff", "-m", "merge", "pr")
        merge = git("rev-parse", "HEAD")
        git("update-ref", "refs/remotes/origin/main", c1)
        return c0, c1, p1, merge

    def run_helper(self, env_extra):
        out_path = self.tmp / "gh_out.txt"
        out_path.write_text("")
        env = {"PATH": os.environ["PATH"], "HOME": str(self.tmp)}
        env.update(env_extra)
        res = subprocess.run([sys.executable, "-I", str(fx.IMPACT_DIR / "base_sha.py"),
                              "--repo", str(self.repo), "--github-output", str(out_path)],
                             env=env, capture_output=True, text=True, timeout=120)
        out = dict(i.split("=", 1) for i in out_path.read_text().split("\n") if "=" in i)
        return res.returncode, out, res

    def test_pull_request_uses_the_first_parent_not_the_frozen_base_sha(self):
        c0, c1, p1, merge = self.build()
        rc, out, res = self.run_helper({
            "EVENT_NAME": "pull_request", "HEAD_SHA": p1, "BASE_REF": "main",
            "PR_BASE_SHA": c0, "GITHUB_SHA": merge})
        self.assertEqual(rc, 0, res.stderr)
        self.assertEqual(out["sha"], c1)
        self.assertNotEqual(out["sha"], c0)
        self.assertEqual(out["reason"], "live-base-first-parent")
        self.assertEqual(res.stdout.split()[0], "sha=" + c1)

    def test_merge_group_uses_the_event_base_sha_never_github_sha(self):
        c0, c1, p1, merge = self.build()
        rc, out, res = self.run_helper({
            "EVENT_NAME": "merge_group", "MERGE_GROUP_BASE_SHA": c1,
            "HEAD_SHA": merge, "BASE_REF": "refs/heads/main", "GITHUB_SHA": merge})
        self.assertEqual(rc, 0, res.stderr)
        self.assertEqual(out["sha"], c1)
        self.assertNotEqual(out["sha"], merge)
        self.assertEqual(out["reason"], "live-base-merge-group")

    def test_a_base_that_contains_the_head_is_refused(self):
        c0, c1, p1, merge = self.build()
        rc, out, res = self.run_helper({
            "EVENT_NAME": "merge_group", "MERGE_GROUP_BASE_SHA": merge,
            "HEAD_SHA": p1, "BASE_REF": "main"})
        self.assertNotEqual(rc, 0)
        self.assertEqual(out["reason"], "base-contains-head")
        self.assertEqual(out["sha"], "")

    def test_a_base_not_on_the_base_ref_is_refused(self):
        c0, c1, p1, merge = self.build()
        rc, out, res = self.run_helper({
            "EVENT_NAME": "merge_group", "MERGE_GROUP_BASE_SHA": p1,
            "HEAD_SHA": merge, "BASE_REF": "main"})
        self.assertNotEqual(rc, 0)
        self.assertEqual(out["reason"], "base-not-on-base-ref")
        self.assertEqual(out["sha"], "")

    def test_an_unsupported_event_fails_closed(self):
        c0, c1, p1, merge = self.build()
        for event in ("push", "workflow_dispatch", "schedule", ""):
            with self.subTest(event=event):
                rc, out, res = self.run_helper({
                    "EVENT_NAME": event, "HEAD_SHA": merge, "BASE_REF": "main",
                    "MERGE_GROUP_BASE_SHA": c1, "GITHUB_SHA": merge})
                self.assertNotEqual(rc, 0)
                self.assertEqual(out["reason"], "base-event-unsupported")
                self.assertEqual(out["sha"], "")

    def test_malformed_inputs_fail_closed(self):
        c0, c1, p1, merge = self.build()
        cases = (
            ({"EVENT_NAME": "merge_group", "MERGE_GROUP_BASE_SHA": "--oops",
              "HEAD_SHA": merge, "BASE_REF": "main"}, "base-sha-invalid"),
            ({"EVENT_NAME": "merge_group", "MERGE_GROUP_BASE_SHA": c1,
              "HEAD_SHA": "zz", "BASE_REF": "main"}, "head-sha-invalid"),
            ({"EVENT_NAME": "merge_group", "MERGE_GROUP_BASE_SHA": c1,
              "HEAD_SHA": merge, "BASE_REF": "../x"}, "base-ref-invalid"),
            ({"EVENT_NAME": "pull_request", "HEAD_SHA": c0, "BASE_REF": "main"},
             "merge-ref-unexpected"),
        )
        for env, reason in cases:
            with self.subTest(reason=reason):
                rc, out, res = self.run_helper(env)
                self.assertNotEqual(rc, 0)
                self.assertEqual(out["reason"], reason)
                self.assertEqual(out["sha"], "")


# F1-F3 (r7): the allow-list reads the PARSED workflow document and the EFFECTIVE
# environment of each pre-trust step, and pins the Materialise run text by content.
# decision: a YAML-parsed effective-environment allow-list and a content hash on the
# Materialise block over a line-oriented text scan because the runner evaluates the
# parsed document and inherited env, so a scanner that sees less than the runner fails open
CHECKOUT_ACTION = "actions/checkout@11d5960a326750d5838078e36cf38b85af677262"
ECHO_RUN = 'echo "enforce=${ENFORCE}" >> "$GITHUB_OUTPUT"'
INDEX_RUN = ('python3 -I "$RUNNER_TEMP/impact-base/impact/build_index.py"'
             ' --repo . --db "$RUNNER_TEMP/impact.db"')
BASE_FOLD_RUN = ('python3 -I "$RUNNER_TEMP/impact-base/impact/gate.py"'
                 ' --needs "$NEEDS_JSON" \\\n  --github-ref "$GITHUB_REF_NAME_FULL"\n')
FORBIDDEN_ENV_RE = re.compile(
    r"^(BASH_ENV|ENV|SHELLOPTS|BASHOPTS|PATH|LD_PRELOAD|LD_LIBRARY_PATH|GIT_.*|PYTHON.*"
    r"|NODE_OPTIONS|RUNNER_TEMP|GITHUB_(PATH|ENV|OUTPUT))$")
HEREDOC = object()
MATERIALISE_ENV = {"CONTEXT_SHA", "EVENT_NAME", "HEAD_SHA", "MERGE_GROUP_BASE_SHA", "IMPACT_FILES"}
# (name, exact top-level keys, exact env keys, exact `with:` mapping, exact run text)
SELECT_ALLOW = (
    (None, {"uses", "with"}, set(), {"fetch-depth": "0", "persist-credentials": "false"}, None),
    ("Selection mode", {"name", "id", "env", "run"}, {"ENFORCE"}, None, ECHO_RUN),
    (MATERIALISE_STEP, {"name", "id", "env", "run"}, MATERIALISE_ENV, None, HEREDOC),
    ("Build impact index", {"name", "if", "continue-on-error", "run"}, set(), None, INDEX_RUN),
)
GATE_ALLOW = (
    (None, {"uses", "with"}, set(), {"fetch-depth": "0", "persist-credentials": "false"}, None),
    (GATE_MATERIALISE_STEP, {"name", "id", "if", "env", "run"}, MATERIALISE_ENV, None, HEREDOC),
    (BASE_GATE_STEP, {"name", "if", "env", "run"}, {"NEEDS_JSON", "GITHUB_REF_NAME_FULL"},
     None, BASE_FOLD_RUN),
)
# job -> (allow-list, first step that may execute checkout content)
WINDOWS = {SELECT_JOB: (SELECT_ALLOW, "Select jobs"),
           GATE_JOB: (GATE_ALLOW, BOOTSTRAP_STEP)}
# The whole effective environment a pre-trust step may inherit: workflow env + job env + step env.
WORKFLOW_ENV_VALUES = {"CARGO_TERM_COLOR": "always",
                       "SELF_HOSTED_TARGET_CAP_BYTES": "42949672960",
                       "CARGO_INCREMENTAL": "0"}
WORKFLOW_ENV_ALLOW = set(WORKFLOW_ENV_VALUES)
JOB_ENV_VALUES = {SELECT_JOB: {"RUSTUP_TOOLCHAIN": "stable"}, GATE_JOB: {}}
JOB_ENV_ALLOW = {job: set(values) for job, values in JOB_ENV_VALUES.items()}
# sec r8 F2: the exact value of every env entry a pre-trust step may carry (a value is the same
# attack surface as a key), the exact job-level key set, runs-on and permissions of both jobs.
GITHUB_SHA_EXPR = "${{ github.sha }}"
HEAD_SHA_EXPR = "${{ github.event.pull_request.head.sha || github.event.merge_group.head_sha }}"
MATERIALISE_ENV_VALUES = {
    "CONTEXT_SHA": GITHUB_SHA_EXPR,
    "EVENT_NAME": "${{ github.event_name }}",
    "HEAD_SHA": HEAD_SHA_EXPR,
    "MERGE_GROUP_BASE_SHA": "${{ github.event.merge_group.base_sha }}",
}
STEP_ENV_VALUES = {
    (SELECT_JOB, "Selection mode"): {"ENFORCE": "${{ vars.CI_IMPACT_ENFORCE }}"},
    (SELECT_JOB, MATERIALISE_STEP): dict(
        MATERIALISE_ENV_VALUES,
        IMPACT_FILES="__init__.py common.py select.py build_index.py gate.py rules.json"),
    (GATE_JOB, GATE_MATERIALISE_STEP): dict(
        MATERIALISE_ENV_VALUES, IMPACT_FILES="__init__.py common.py gate.py rules.json"),
    (GATE_JOB, BASE_GATE_STEP): {"NEEDS_JSON": "${{ toJSON(needs) }}",
                                 "GITHUB_REF_NAME_FULL": "${{ github.ref }}"},
}
JOB_KEY_SETS = {
    SELECT_JOB: sorted(["name", "runs-on", "timeout-minutes", "env", "outputs", "steps"]),
    GATE_JOB: sorted(["name", "if", "needs", "runs-on", "timeout-minutes", "steps"]),
}
JOB_RUNS_ON = "ubuntu-latest"
JOB_TIMEOUT_MINUTES = {SELECT_JOB: "15", GATE_JOB: "5"}  # code r13 F2: ci.yml:173 and :2770
JOB_NAMES = {SELECT_JOB: "Impact selection", GATE_JOB: "ci-gate"}  # sec r13 S2
# sec r14 S2 / sec r15 A: the only job display names that hold an expression (matrix legs), each
# bound to its job id and to the matrix key it renders; any other `${{` in a job name, the same
# value on another job, or the value on its own job without that matrix key, is a problem line
# (13 job names are checked at head, 2 of them hold a matrix name). ci.yml holds both jobs:
# `check` (matrix.include entries carry `leg`) and `mobile-cross-compile` (entries carry `target`).
JOB_MATRIX_NAMES = {
    "check": ("Check (${{ matrix.leg }})", "leg"),
    "mobile-cross-compile": ("Cross-compile (${{ matrix.target }})", "target"),
}
JOB_NAME_EXPRESSIONS = {name for name, _ in JOB_MATRIX_NAMES.values()}
NULL_SPELLINGS = ("null", "~")  # YAML 1.1/1.2 core null spellings, any case (sec r15 B)
JOB_PERMISSIONS = None  # neither job sets `permissions`; the workflow-level block applies
WORKFLOW_PERMISSIONS = {"contents": "read"}
JOB_KEYS_REFUSED = ("container", "services")
STEP_KEYS_REFUSED = ("shell", "working-directory")
# sha256 of the normalised `run:` text of each Materialise step (see run_digest).
MATERIALISE_SHA256 = {
    MATERIALISE_STEP: "7c5fbf963de63f69b8715375a039868e33060d839649eb6029d7689e8f946995",
    GATE_MATERIALISE_STEP: "7c5fbf963de63f69b8715375a039868e33060d839649eb6029d7689e8f946995",
}
# The only names a Materialise body may spell as a path: git tree paths and the .git state
# files it REFUSES. Anything else that names a file under the checkout is red.
MATERIALISE_PATH_WORDS = {"scripts/ci/impact/", "scripts/ci/impact/gate.py", "refs/replace/",
                          "info/grafts", "objects/info/alternates",
                          "gate.py"}  # "gate.py" is joined onto the impact git tree prefix
MATERIALISE_IMPORTS = {"os", "re", "shutil", "subprocess", "sys", "pathlib"}
MATERIALISE_REFUSED_ATTRS = {"system", "popen", "Popen", "execv", "execve", "execl", "execlp",
                             "execvp", "execvpe", "spawnv", "spawnl", "load_module", "run_path",
                             "run_module", "startfile", "import_module"}
MATERIALISE_REFUSED_NAMES = MATERIALISE_REFUSED_ATTRS | {"exec", "eval", "compile", "__import__",
                                                         "runpy", "importlib"}
PATH_LIKE_RE = re.compile(r"/|\.py$|\.sh$|\.env$|^\.")
# sec F1 / code C1-C3 (round 12), sec r10 S1-S4 (round 13), code r10 C1-C4 (round 13) and
# sec r11 S1-S5 (round 14): the
# second layer is a POSITIVE ALLOW-LIST over the parsed body. With the sha256 pin re-pinned to a
# mutated body it enforces exactly the rules below and no more.
# parse model: the heredoc body ends at the first terminator line, and a text with anything after
# it is not one bare heredoc (the first terminator line is what the shell uses).
# call targets: a bare name in MATERIALISE_NAME_CALLS, or a rendered receiver chain listed in
# MATERIALISE_MODULE_CHAINS or MATERIALISE_METHOD_CHAINS (any other receiver is a problem line);
# an allowed module chain is accepted in call position only: as an argument, keyword value or
# assigned value it is a problem line, except os.environ (read-only rule) and the exception class
# subprocess.TimeoutExpired as an `except` type (MATERIALISE_VALUE_CHAINS).
# pinned imports: exactly the statements in MATERIALISE_IMPORT_STATEMENTS, no `as` and no other
# module; no rebinding: no assignment, parameter, loop, with, except, comprehension or match
# target binds an allowed name or a module root, and a function or class is defined only under a
# pinned name; match and lambda are refused.
# exact argv head: the one subprocess.run argv is the two literals of MATERIALISE_GIT_ARGV plus
# `list(args)`; argv tail: `args` must be an unrebound parameter of the enclosing function, that
# is exactly one binding (the parameter) and no assignment, augmented or annotated assignment,
# walrus, for, with, comprehension, match or import binding of `args` in that function.
# dash literals: a string constant starting with a dash must be in MATERIALISE_DASH_ARGS, and every
# git() argument is a string literal or one of the pinned expressions in
# MATERIALISE_GIT_VALUE_ARGS. Enumerated call arguments (sec r11 S2, S5): every call of a local
# function, of print and of shutil.rmtree takes exactly one of the argument texts listed for it in
# MATERIALISE_CALL_ARGS (no keyword, no starred, no expression built from literals or calls), and
# each name in the argument of a git value sink resolves by its binding.
# names resolved by binding: each name in a pinned git expression, in an open() or Path() argument
# and the root name of every method call has exactly one binding in its function, and that
# binding is the enumerated one in MATERIALISE_VALUE_BINDINGS (an unrebound parameter, a single
# pinned assignment, a single pinned for loop, or only `with open(...)` for handle). The four
# module-level names IMPACT_PREFIX, SHA_RE, REGULAR_MODES and GIT_TIMEOUT_S each have exactly ONE
# binding in the whole body: a direct module-body assignment with a single Name target and the
# value pinned in MATERIALISE_CONST_BINDINGS, checked whether or not the name is read (code r12
# C1). A second assignment, a changed value, a multi-target assignment and an assignment under
# if, try or while are each a problem line. Any other binding is a problem line.
# environment untouched, read-only environment uses (sec r11 S1): the child environment is the
# pinned copy, unmodified. The pinned environment construction is the one statement
# `env = dict(os.environ, GIT_NO_REPLACE_OBJECTS='1')` (MATERIALISE_ENV_CONSTRUCTION) in git(),
# bound to the one name env; the `env=` keyword of the one subprocess.run is that name; every other
# dict() call, mapping literal or comprehension, copy, copy of a copy, `env=None`, missing `env=`
# and any other `env=` value is a problem line. Every other name bound from os.environ (an alias,
# a parameter that receives it) and os.environ itself may only be read through a subscript load,
# .get, .items, .keys, .values, `in`, or the one call derive_base(os.environ); every other
# reference, store, delete, update, pop, clear or pass-on is a problem line, and the body has no
# subscript store. No decorator and no class keyword (they call without a Call node), no type
# parameter and no type alias (sec r11 S3, S4), and no parameter default as a value binding.
# open() takes only the enumerated MATERIALISE_OPEN_ARGS with mode "a", Path() only
# MATERIALISE_PATH_ARGS, and the `__main__` guard is the last top-level statement and holds
# exactly `sys.exit(main())`.
# The layer does not check runtime values (environment variable contents, the IMPACT_FILES names,
# fetched blob bytes). It DOES pin what the local functions do (sec r13 S1, code r13 F1): the
# normalised ast.dump of every class and function the heredoc defines is compared with the pinned
# text MATERIALISE_FUNCTION_PINS, so a runner-conditioned or unconditional edit of a branch, a
# return or a call in derive_base, rev_parse, materialise, gate_absent, report or main is a
# problem line naming the function, whatever the sha256 pin says. The module body outside those
# functions is pinned too (sec r14 S1, the pinned module body): the ast.dump of the whole module with every class and
# function body elided to `pass` is compared with MATERIALISE_MODULE_PIN, so the imports, the
# constants, the order of the definitions and the guard are exactly the pinned sequence and a
# module-level statement anywhere is a problem line naming "module body". Functions AND module
# body are therefore pinned; the sha256 digest stays the primary pin.
MATERIALISE_ENFORCES = ("call targets", "pinned imports", "no rebinding", "exact argv head",
                        "dash literals", "environment untouched",
                        "unrebound parameter", "exactly one binding",
                        "read-only environment uses", "pinned function control flow",
                        "pinned module body")
MATERIALISE_MODULE_ROOTS = {"os", "re", "shutil", "subprocess", "sys", "pathlib"}
MATERIALISE_IMPORT_STATEMENTS = sorted(["from pathlib import Path", "import os", "import re",
                                        "import shutil", "import subprocess", "import sys"])
MATERIALISE_MODULE_CHAINS = {"os.environ", "os.environ.get", "os.path.lexists", "re.compile",
                             "shutil.rmtree", "subprocess.TimeoutExpired", "subprocess.run",
                             "sys.exit"}
# Receiver chains of method calls on values; a call is rendered as `()` in the chain.
MATERIALISE_METHOD_CHAINS = sorted([
    "SHA_RE.match", "dest.exists", "dest.is_dir", "dest.is_symlink", "env.get", "handle.write",
    "listed.stdout.strip", "os.environ.get().split", "res.stdout.decode", "res.stdout.decode().strip",
    "res.stdout.strip", "target.parent.mkdir", "target.write_bytes", "tree.stdout.decode",
    "tree.stdout.decode().split", "tree.stdout.strip"])
MATERIALISE_ENVIRON_WRITERS = sorted(["os.environ.clear", "os.environ.pop", "os.environ.popitem",
                                      "os.environ.setdefault", "os.environ.update", "os.putenv",
                                      "os.unsetenv"])
MATERIALISE_DEFINED_NAMES = sorted(["BaseUnavailable", "derive_base", "fetch_blob", "gate_absent",
                                    "git", "git_state_refused", "have_commit", "main",
                                    "materialise", "replace_refs_present", "report", "rev_parse"])
MATERIALISE_NAME_CALLS = {"BaseUnavailable", "Path", "bool", "derive_base", "dict", "fetch_blob",
                          "gate_absent", "git", "git_state_refused", "have_commit", "len", "list",
                          "main", "materialise", "open", "print", "replace_refs_present",
                          "report", "rev_parse", "str"}
MATERIALISE_GIT_SUBCOMMANDS = {"cat-file", "fetch", "for-each-ref", "ls-tree", "replace",
                               "rev-parse", "show"}
MATERIALISE_DASH_ARGS = {"--", "--count=1", "--depth=1", "--format=%(refname)", "--git-path",
                         "--list", "--no-replace-objects", "--no-tags", "--quiet", "--verify",
                         "-e"}
# Non-literal git() arguments, by their unparsed spelling.
MATERIALISE_GIT_VALUE_ARGS = sorted(["'%s:%s' % (base, path)", "IMPACT_PREFIX + 'gate.py'",
                                     "base", "base + '^{commit}'", "path", "rel", "spec"])
MATERIALISE_RUN_KEYWORDS = {"capture_output", "env", "timeout"}
MATERIALISE_GIT_ARGV = ("git", "--no-replace-objects")
MATERIALISE_RUN_ARGV_TAIL = "list(args)"
# code r10 C1-C4: the one accepted binding of each name a git() argument depends on, keyed by
# (function, name). "param" is an unrebound parameter, "for-literal" the single loop target over
# a tuple of string literals, any other string the unparsed value of the single assignment.
MATERIALISE_VALUE_BINDINGS = {
    ("derive_base", "context"): "env.get('CONTEXT_SHA', '')",
    ("derive_base", "env"): "param",
    ("fetch_blob", "base"): "param",
    ("fetch_blob", "name"): "param",
    ("fetch_blob", "path"): "IMPACT_PREFIX + name",
    ("fetch_blob", "tree"): "git('ls-tree', base, '--', path)",
    ("gate_absent", "base"): "param",
    ("gate_absent", "tree"): "git('ls-tree', base, '--', IMPACT_PREFIX + 'gate.py')",
    ("git_state_refused", "rel"): "for:('info/grafts', 'shallow', 'objects/info/alternates')",
    ("git_state_refused", "res"): "git('rev-parse', '--git-path', rel)",
    ("git", "env"): "dict(os.environ, GIT_NO_REPLACE_OBJECTS='1')",
    ("have_commit", "base"): "param",
    ("main", "dest"): "Path(os.environ['RUNNER_TEMP']) / 'impact-base'",
    ("main", "derived"): ("''", "derive_base(os.environ)"),
    ("main", "names"): "os.environ.get('IMPACT_FILES', '').split()",
    ("materialise", "base"): "param",
    ("materialise", "dest"): "param",
    ("materialise", "name"): "for:names",
    ("materialise", "names"): "param",
    ("materialise", "target"): "dest / 'impact' / name",
    ("replace_refs_present", "listed"): "git('replace', '--list')",
    ("replace_refs_present", "res"):
        "git('for-each-ref', '--count=1', '--format=%(refname)', 'refs/replace/')",
    ("report", "bootstrap"): "param-default:False",
    ("report", "handle"): "with-open",
    ("report", "line"): "line-accum",
    ("report", "ok"): "param",
    ("report", "reason"): "param",
    ("report", "summary"): "os.environ.get('GITHUB_STEP_SUMMARY')",
    ("rev_parse", "res"): "git('rev-parse', '--verify', '--quiet', spec)",
    ("rev_parse", "spec"): "param",
}
# Module-level names: the only names the body binds at module level (code r11 C1). Each has a
# pinned value and exactly ONE binding, a direct module-body assignment of that value with a single
# Name target (code r12 C1); an allow-list of names alone would accept any value and any number of
# bindings.
MATERIALISE_MODULE_STORES = {"SHA_RE", "REGULAR_MODES", "IMPACT_PREFIX", "GIT_TIMEOUT_S"}
MATERIALISE_CONST_BINDINGS = {"IMPACT_PREFIX": "'scripts/ci/impact/'",
                              "SHA_RE": "re.compile('^[0-9a-f]{40}$')",
                              "REGULAR_MODES": "('100644', '100755')",
                              "GIT_TIMEOUT_S": "120"}
# Module chains read as a VALUE rather than called: the environment (checked by the read-only rule)
# and the one exception class, which is accepted only as an `except` type.
MATERIALISE_VALUE_CHAINS = {"os.environ", "subprocess.TimeoutExpired"}
MATERIALISE_ENV_PARAMS = {"env"}  # parameters that receive os.environ (derive_base)
MATERIALISE_ENV_READS = {"get", "items", "keys", "values"}
# sec r11 S1: the ONE accepted environment construction (the exact unparsed statement value) and
# the function that holds it; the one accepted pass-on of os.environ is derive_base(os.environ).
MATERIALISE_ENV_CONSTRUCTION = "dict(os.environ, GIT_NO_REPLACE_OBJECTS='1')"
MATERIALISE_ENV_SCOPE = "git"
MATERIALISE_ENV_NAME = "env"
MATERIALISE_ENV_PASS_ON = "derive_base(os.environ)"
# sec r11 S2/S5: the argument texts (unparsed, keywords as k=v) each call may carry, by callee.
MATERIALISE_CALL_ARGS = {
    "BaseUnavailable": sorted(["'base-event-unsupported'", "'base-fetch-failed'",
                               "'base-file-missing:' + name", "'base-file-not-regular:' + name",
                               "'base-read-failed:' + name", "'base-sha-invalid'",
                               "'base-sha-mismatch'", "'dest-unsafe'", "'git-failed'",
                               "'no-files-listed'", "'write-failed'"]),
    "derive_base": ["os.environ"],
    "fetch_blob": ["base, name"],
    "gate_absent": ["derived"],
    "git_state_refused": [""],
    "handle.write": sorted(["'bootstrap=%s\\n' % ('true' if bootstrap else 'false')",
                            "'ok=%s\\n' % ('true' if ok else 'false')",
                            "'reason=%s\\n' % reason", "line + '\\n'"]),
    "have_commit": ["base"],
    "main": [""],
    "materialise": ["derived, dest, names"],
    "print": sorted(["'impact: derived base %s from github.sha %s' % "
                     "(derived, os.environ.get('CONTEXT_SHA', ''))",
                     "'impact: selector files loaded from the base sha'", "line"]),
    "replace_refs_present": [""],
    "report": sorted(["False, 'environment-unusable'", "False, str(exc), gate_absent(derived)",
                      "True, ''"]),
    "rev_parse": sorted(["'HEAD^{commit}'", "context + '^1^{commit}'", "context + '^2^{commit}'"]),
    "shutil.rmtree": ["str(dest)", "str(dest), ignore_errors=True"],
}
# sec r12 R2: the two statements that build `line` in report(): the one assignment and the one
# augmented literal.
MATERIALISE_LINE_ASSIGN = "'impact: base files unavailable (%s)' % reason"
MATERIALISE_LINE_AUGMENT = "'; bootstrap: the base sha has no scripts/ci/impact/gate.py'"
# Callees whose arguments reach git (or delete a tree): each name in an argument must resolve by
# its binding.
MATERIALISE_CALL_SINKS = {"fetch_blob", "gate_absent", "have_commit", "materialise", "rev_parse",
                          "shutil.rmtree"}
# sec r12 R1/R2: print and the step output writes carry values into the job log, the step summary
# and the step outputs, so the names in their arguments resolve by binding as well.
MATERIALISE_OUTPUT_SINKS = MATERIALISE_CALL_SINKS | {"handle.write", "print"}
MATERIALISE_CALL_KINDS = {"handle.write": "step output write", "print": "print call",
                          "shutil.rmtree": "rmtree call"}
MATERIALISE_OPEN_ARGS = sorted(["os.environ['GITHUB_OUTPUT']", "summary"])
MATERIALISE_PATH_ARGS = sorted(["os.environ['RUNNER_TEMP']"])
MATERIALISE_GUARD_TEST = "__name__ == '__main__'"
MATERIALISE_GUARD_BODY = ["sys.exit(main())"]
# code r13 F1 / sec r13 S1: the text of every class and function of the Materialise heredoc (ci.yml
# :241-415 of the select job and its twin :2824-2998 of the gate job; the two bodies are byte
# identical, the sha256 pin is the same). The second layer compares the normalised ast.dump (no
# attributes, so no line numbers) of the defined name in the checked body with the dump of the text
# here; comments and blank lines do not count. The set of keys is exactly MATERIALISE_DEFINED_NAMES.
MATERIALISE_FUNCTION_PINS = {
    "BaseUnavailable": r'''class BaseUnavailable(Exception):
    """The base copy cannot be built; the reason is a fixed token."""
''',
    "git": r'''def git(*args):
    # --no-replace-objects and GIT_NO_REPLACE_OBJECTS=1 ignore replace
    # refs only; grafts, shallow files and alternates are refused by
    # git_state_refused() before the derivation reads anything.
    env = dict(os.environ, GIT_NO_REPLACE_OBJECTS="1")
    try:
        return subprocess.run(["git", "--no-replace-objects"] + list(args),
                              capture_output=True, timeout=GIT_TIMEOUT_S,
                              env=env)
    except (OSError, subprocess.TimeoutExpired):
        raise BaseUnavailable("git-failed")
''',
    "have_commit": r'''def have_commit(base):
    return git("cat-file", "-e", base + "^{commit}").returncode == 0
''',
    "fetch_blob": r'''def fetch_blob(base, name):
    path = IMPACT_PREFIX + name
    tree = git("ls-tree", base, "--", path)
    if tree.returncode != 0:
        raise BaseUnavailable("base-read-failed:" + name)
    fields = tree.stdout.decode("utf-8", "replace").split()
    if len(fields) < 4:
        raise BaseUnavailable("base-file-missing:" + name)
    if fields[1] != "blob" or fields[0] not in REGULAR_MODES:
        raise BaseUnavailable("base-file-not-regular:" + name)
    blob = git("show", "%s:%s" % (base, path))
    if blob.returncode != 0 or not blob.stdout:
        raise BaseUnavailable("base-read-failed:" + name)
    return blob.stdout
''',
    "rev_parse": r'''def rev_parse(spec):
    res = git("rev-parse", "--verify", "--quiet", spec)
    value = res.stdout.decode("utf-8", "replace").strip()
    return value if res.returncode == 0 and SHA_RE.match(value) else ""
''',
    "replace_refs_present": r'''def replace_refs_present():
    # Any refs/replace entry is unexpected on a fresh checkout: fail
    # closed. Both the ref namespace and `git replace --list` are read.
    res = git("for-each-ref", "--count=1", "--format=%(refname)", "refs/replace/")
    if res.returncode != 0 or res.stdout.strip():
        return True
    listed = git("replace", "--list")
    return listed.returncode != 0 or bool(listed.stdout.strip())
''',
    "git_state_refused": r'''def git_state_refused():
    # Fail closed on every git state the runner can carry into the
    # derivation. fetch-depth 0 produces a full clone: no shallow file,
    # no grafts, no alternates (replace refs are read by
    # replace_refs_present()); any of them, or the env vars that
    # point git at one, is refused. Only the reason
    # token is ever reported, never a path or author text.
    for var in ("GIT_GRAFT_FILE", "GIT_ALTERNATE_OBJECT_DIRECTORIES",
                "GIT_OBJECT_DIRECTORY"):
        if os.environ.get(var):
            return True
    for rel in ("info/grafts", "shallow", "objects/info/alternates"):
        res = git("rev-parse", "--git-path", rel)
        path = res.stdout.decode("utf-8", "replace").strip()
        if res.returncode != 0 or not path or os.path.lexists(path):
            return True
    return False
''',
    "derive_base": r'''def derive_base(env):
    # The authority: git and the event payload, never a resolver. The
    # checked-out commit must be exactly the github.sha context value
    # (the merge ref); a moved HEAD, a replace ref, grafts, a shallow file
    # or alternates is a mismatch.
    event = env.get("EVENT_NAME", "")
    context = env.get("CONTEXT_SHA", "")
    if event in ("pull_request", "merge_group"):
        if not SHA_RE.match(context) or rev_parse("HEAD^{commit}") != context:
            raise BaseUnavailable("base-sha-mismatch")
        if replace_refs_present() or git_state_refused():
            raise BaseUnavailable("base-sha-mismatch")
    if event == "pull_request":
        head = env.get("HEAD_SHA", "")
        if not SHA_RE.match(head) or rev_parse(context + "^2^{commit}") != head:
            raise BaseUnavailable("base-sha-mismatch")
        parent = rev_parse(context + "^1^{commit}")
        if not parent:
            raise BaseUnavailable("base-sha-mismatch")
        return parent
    if event == "merge_group":
        raw = env.get("MERGE_GROUP_BASE_SHA", "")
        if not SHA_RE.match(raw):
            raise BaseUnavailable("base-sha-invalid")
        return raw
    raise BaseUnavailable("base-event-unsupported")
''',
    "gate_absent": r'''def gate_absent(base):
    # Bootstrap is exactly: the base tree lists no gate.py. A failed
    # read (bad sha, missing commit, git error) is never bootstrap.
    try:
        if not SHA_RE.match(base) or not have_commit(base):
            return False
        tree = git("ls-tree", base, "--", IMPACT_PREFIX + "gate.py")
    except BaseUnavailable:
        return False
    return tree.returncode == 0 and not tree.stdout.strip()
''',
    "materialise": r'''def materialise(base, dest, names):
    if not SHA_RE.match(base):
        raise BaseUnavailable("base-sha-invalid")
    if not have_commit(base):
        git("fetch", "--no-tags", "--depth=1", "origin", base)
        if not have_commit(base):
            raise BaseUnavailable("base-fetch-failed")
    if dest.is_symlink() or (dest.exists() and not dest.is_dir()):
        raise BaseUnavailable("dest-unsafe")
    if dest.exists():
        shutil.rmtree(str(dest))
    try:
        for name in names:
            blob = fetch_blob(base, name)
            target = dest / "impact" / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(blob)
    except OSError:
        shutil.rmtree(str(dest), ignore_errors=True)
        raise BaseUnavailable("write-failed")
    except BaseException:
        shutil.rmtree(str(dest), ignore_errors=True)
        raise
''',
    "report": r'''def report(ok, reason, bootstrap=False):
    with open(os.environ["GITHUB_OUTPUT"], "a") as handle:
        handle.write("ok=%s\n" % ("true" if ok else "false"))
        handle.write("bootstrap=%s\n" % ("true" if bootstrap else "false"))
        handle.write("reason=%s\n" % reason)
    if ok:
        print("impact: selector files loaded from the base sha")
        return
    line = "impact: base files unavailable (%s)" % reason
    if bootstrap:
        line += "; bootstrap: the base sha has no scripts/ci/impact/gate.py"
    print(line)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as handle:
            handle.write(line + "\n")
''',
    "main": r'''def main():
    derived = ""
    try:
        dest = Path(os.environ["RUNNER_TEMP"]) / "impact-base"
        names = os.environ.get("IMPACT_FILES", "").split()
        if not names:
            raise BaseUnavailable("no-files-listed")
        derived = derive_base(os.environ)
        print("impact: derived base %s from github.sha %s"
              % (derived, os.environ.get("CONTEXT_SHA", "")))
        materialise(derived, dest, names)
    except BaseUnavailable as exc:
        report(False, str(exc), gate_absent(derived))
        return 0
    except (OSError, KeyError):
        report(False, "environment-unusable")
        return 0
    report(True, "")
    return 0
''',
}
MATERIALISE_FUNCTION_DUMPS = {name: ast.dump(ast.parse(text).body[0])
                              for name, text in MATERIALISE_FUNCTION_PINS.items()}
# sec r14 S1: the module body of the Materialise heredoc (ci.yml:228-418 of the select job and its
# twin :2811-3001 of the gate job) as one ordered statement sequence: the imports, the four pinned
# constants, the 12 definitions in order and the `__main__` guard. Every class and function body
# is elided to `pass` here and in the checked tree (the per-function pins above compare the
# bodies), so the module pin covers everything between and around the definitions and accepts
# exactly one module body: a statement inserted, moved, repeated or appended is a problem line
# naming "module body".
MATERIALISE_MODULE_PIN = r'''import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
REGULAR_MODES = ("100644", "100755")
IMPACT_PREFIX = "scripts/ci/impact/"
GIT_TIMEOUT_S = 120


class BaseUnavailable(Exception):
    pass


def git(*args):
    pass


def have_commit(base):
    pass


def fetch_blob(base, name):
    pass


def rev_parse(spec):
    pass


def replace_refs_present():
    pass


def git_state_refused():
    pass


def derive_base(env):
    pass


def gate_absent(base):
    pass


def materialise(base, dest, names):
    pass


def report(ok, reason, bootstrap=False):
    pass


def main():
    pass


if __name__ == "__main__":
    sys.exit(main())
'''


def _elided_module_dump(tree):
    """The ast.dump of a module with every top-level class and function body replaced by `pass`."""
    body = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            node = copy.copy(node)
            node.body = [ast.Pass()]
        body.append(node)
    return ast.dump(ast.Module(body=body, type_ignores=[]))


MATERIALISE_MODULE_DUMP = _elided_module_dump(ast.parse(MATERIALISE_MODULE_PIN))


def _chain(node):
    """Render a call target as `a.b.c`; a call inside the receiver is rendered `()`. None for any
    other receiver (subscript, constant, lambda, ...)."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        inner = _chain(node.value)
        return None if inner is None else "%s.%s" % (inner, node.attr)
    if isinstance(node, ast.Call):
        inner = _chain(node.func)
        return None if inner is None else inner + "()"
    return None


def _bound_names(tree):
    """(name, kind, statement) for every binding in the tree; kind is store, def, arg, import."""
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            found.append((node.id, "store", node))
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            found.append((node.name, "def", node))
        elif isinstance(node, ast.arg):
            found.append((node.arg, "arg", node))
        elif isinstance(node, ast.ExceptHandler) and node.name:
            found.append((node.name, "store", node))
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                found.append(((alias.asname or alias.name).split(".")[0], "import", node))
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            found.extend((name, "store", node) for name in node.names)
        elif type(node).__name__ in ("TypeVar", "ParamSpec", "TypeVarTuple"):
            found.append((node.name, "store", node))  # PEP 695 type parameters (3.12+)
        elif type(node).__name__ in ("MatchAs", "MatchStar") and node.name:
            found.append((node.name, "store", node))  # match capture patterns (3.10+)
        elif type(node).__name__ == "MatchMapping" and node.rest:
            found.append((node.rest, "store", node))
    return found


def _binding_problems(label, tree):
    problems = []
    protected = MATERIALISE_NAME_CALLS | MATERIALISE_MODULE_ROOTS
    defs = {}
    for name, kind, node in _bound_names(tree):
        if kind == "import":
            if ast.unparse(node) not in MATERIALISE_IMPORT_STATEMENTS or len(node.names) != 1:
                problems.append("%s: import statement outside the pinned set (%s)"
                                % (label, ast.unparse(node)))
        elif kind == "def" and name in MATERIALISE_DEFINED_NAMES:
            defs[name] = defs.get(name, 0) + 1
            if defs[name] > 1:
                problems.append("%s: %s defined more than once" % (label, name))
        elif name in protected:
            problems.append("%s: binds %s (an allowed name or a module root)" % (label, name))
        elif kind == "def":
            problems.append("%s: defines %s outside the pinned set" % (label, name))
    return problems


def _parents(tree):
    return {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}


def _scope_of(node, parents):
    """The enclosing function definition of a node, or None at module level."""
    cur = parents.get(node)
    while cur is not None and not isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef)):
        cur = parents.get(cur)
    return cur


def _local_bindings(scope, name):
    """Every binding of `name` inside the function (parameters included, the def itself not)."""
    return [b for b in _bound_names(scope) if b[0] == name and b[2] is not scope]


def _param_ok(scope, name):
    """True when `name` has exactly one binding in the function and it is a parameter."""
    if scope is None:
        return False
    params = list(ast.walk(scope.args))
    local = _local_bindings(scope, name)
    return (len(local) == 1 and local[0][1] == "arg" and any(local[0][2] is p for p in params)
            and not _has_default(scope, local[0][2]))


def _default_text(scope, arg):
    """The unparsed default value of a parameter, or None when it has none."""
    spec = scope.args
    positional = list(spec.posonlyargs) + list(spec.args)
    for index, item in enumerate(positional):
        if item is arg:
            at = index - (len(positional) - len(spec.defaults))
            return ast.unparse(spec.defaults[at]) if at >= 0 else None
    for item, default in zip(spec.kwonlyargs, spec.kw_defaults):
        if item is arg:
            return ast.unparse(default) if default is not None else None
    return None


def _has_default(scope, arg):
    """True when the parameter carries a default value (a default is a value binding of its own)."""
    spec = scope.args
    positional = list(spec.posonlyargs) + list(spec.args)
    for index, item in enumerate(positional):
        if item is arg:
            return index >= len(positional) - len(spec.defaults)
    for item, default in zip(spec.kwonlyargs, spec.kw_defaults):
        if item is arg:
            return default is not None
    return False


def _name_problems(tree, parents, scope, name, seen=()):
    """Reasons `name` does not resolve to its one enumerated binding (empty when it does)."""
    if name in seen:
        return []
    if name in MATERIALISE_CONST_BINDINGS:
        found = [b for b in _bound_names(tree) if b[0] == name]
        assign = parents.get(found[0][2]) if len(found) == 1 else None
        ok = (isinstance(assign, ast.Assign) and parents.get(assign) is tree
              and len(assign.targets) == 1
              and ast.unparse(assign.value) == MATERIALISE_CONST_BINDINGS[name])
        return [] if ok else ["%s has no single module-level binding to its constant" % name]
    if scope is None:
        return ["%s is used at module level without an enumerated binding" % name]
    expected = MATERIALISE_VALUE_BINDINGS.get((scope.name if scope else None, name))
    if expected is None:
        return ["%s is not an enumerated value name in its function" % name]
    if expected == "param":
        return [] if _param_ok(scope, name) else [
            "%s is not an unrebound parameter without a default" % name]
    local = _local_bindings(scope, name)
    if isinstance(expected, str) and expected.startswith("param-default:"):
        default = expected.split(":", 1)[1]
        ok = (len(local) == 1 and local[0][1] == "arg"
              and any(local[0][2] is p for p in ast.walk(scope.args))
              and _default_text(scope, local[0][2]) == default)
        return [] if ok else ["%s is not an unrebound parameter with its pinned default" % name]
    if expected == "line-accum":
        sites = [parents.get(b[2]) for b in local]
        assigns = [s for b, s in zip(local, sites) if b[1] == "store" and isinstance(s, ast.Assign)
                   and len(s.targets) == 1 and s.targets[0] is b[2]]
        augments = [s for b, s in zip(local, sites) if b[1] == "store"
                    and isinstance(s, ast.AugAssign) and s.target is b[2]
                    and isinstance(s.op, ast.Add)]
        ok = (len(local) == 2 and len(assigns) == 1 and len(augments) == 1
              and ast.unparse(assigns[0].value) == MATERIALISE_LINE_ASSIGN
              and ast.unparse(augments[0].value) == MATERIALISE_LINE_AUGMENT)
        if not ok:
            return ["%s is not bound only to its pinned assignment and one pinned augmented "
                    "literal" % name]
        guard = parents.get(augments[0])
        body = scope.body
        direct = (isinstance(guard, ast.If) and ast.unparse(guard.test) == "bootstrap"
                  and not guard.orelse and guard.body == [augments[0]]
                  and any(a is assigns[0] and i + 1 < len(body) and body[i + 1] is guard
                          for i, a in enumerate(body)))
        if not direct:
            return ["%s augmented literal is not the sole body of `if bootstrap:` directly after "
                    "its pinned assignment in report()" % name]
        return _value_name_problems("line", tree, parents, assigns[0], assigns[0].value)
    if isinstance(expected, tuple):
        sites = [parents.get(b[2]) for b in local]
        ok = (len(local) == len(expected) and all(
            b[1] == "store" and isinstance(s, ast.Assign) and len(s.targets) == 1
            and s.targets[0] is b[2] for b, s in zip(local, sites))
            and sorted(ast.unparse(s.value) for s in sites if isinstance(s, ast.Assign))
            == sorted(expected))
        return [] if ok else ["%s is not bound only to %s" % (name, " and ".join(expected))]
    if expected == "with-open":
        sites = [parents.get(b[2]) for b in local]
        ok = bool(local) and all(
            b[1] == "store" and isinstance(s, ast.withitem) and s.optional_vars is b[2]
            and isinstance(s.context_expr, ast.Call) and isinstance(s.context_expr.func, ast.Name)
            and s.context_expr.func.id == "open" for b, s in zip(local, sites))
        return [] if ok else ["%s is not only bound by `with open(...)`" % name]
    if len(local) != 1 or local[0][1] != "store":
        return ["%s does not have exactly one binding" % name]
    site = parents.get(local[0][2])
    if expected.startswith("for:"):
        source = expected[4:]
        if not (isinstance(site, ast.For) and site.target is local[0][2]
                and ast.unparse(site.iter) == source):
            return ["%s is not the single loop target over %s" % (name, source)]
        value = site.iter
    else:
        if not (isinstance(site, ast.Assign) and len(site.targets) == 1
                and site.targets[0] is local[0][2] and ast.unparse(site.value) == expected):
            return ["%s is not bound once to %s" % (name, expected)]
        value = site.value
    problems = []
    for inner in ast.walk(value):
        if (isinstance(inner, ast.Name) and isinstance(inner.ctx, ast.Load)
                and inner.id not in MATERIALISE_MODULE_ROOTS
                and inner.id not in MATERIALISE_NAME_CALLS):
            problems.extend(_name_problems(tree, parents, scope, inner.id, seen + (name,)))
    return problems


def _value_name_problems(label, tree, parents, node, expr, what="git value name"):
    scope = _scope_of(node, parents)
    problems = []
    for inner in ast.walk(expr):
        if isinstance(inner, ast.Name) and inner.id not in MATERIALISE_MODULE_ROOTS \
                and inner.id not in MATERIALISE_NAME_CALLS:
            problems.extend("%s: %s %s: %s" % (label, what, inner.id, why) for why in
                            _name_problems(tree, parents, scope, inner.id)[:1])
    return problems


def _receiver_problems(label, tree, parents, node):
    """A method call on a value: the receiver root name must resolve to its enumerated binding."""
    root = node.func
    while isinstance(root, (ast.Attribute, ast.Call)):
        root = root.value if isinstance(root, ast.Attribute) else root.func
    if not isinstance(root, ast.Name) or root.id in MATERIALISE_MODULE_ROOTS \
            or root.id in MATERIALISE_NAME_CALLS:
        return []
    return _value_name_problems(label, tree, parents, node, root, "method receiver name")


def _open_path_problems(label, tree, parents, node, kind):
    """open() and Path() take only the enumerated pinned arguments."""
    args = node.args
    if kind == "open":
        shape = (len(args) == 2 and not node.keywords and ast.unparse(args[0]) in MATERIALISE_OPEN_ARGS
                 and isinstance(args[1], ast.Constant) and args[1].value == "a")
        pinned = MATERIALISE_OPEN_ARGS
    else:
        shape = len(args) == 1 and not node.keywords and ast.unparse(args[0]) in MATERIALISE_PATH_ARGS
        pinned = MATERIALISE_PATH_ARGS
    if not shape:
        return ["%s: %s call outside the enumerated arguments %s" % (label, kind, pinned)]
    return _value_name_problems(label, tree, parents, node, args[0])


def _is_mapping(expr, names):
    """True when the expression evaluates to the environment mapping itself or a copy of it."""
    if isinstance(expr, ast.Name):
        return expr.id in names
    if isinstance(expr, ast.Attribute):
        return _chain(expr) == "os.environ"
    if isinstance(expr, ast.Call):
        func = expr.func
        if isinstance(func, ast.Name) and func.id == "dict":
            return any(_is_mapping(a, names) for a in expr.args)
        if isinstance(func, ast.Attribute) and func.attr == "copy":
            return _is_mapping(func.value, names)
        return False
    if isinstance(expr, ast.Dict):
        return any(k is None and _is_mapping(v, names) for k, v in zip(expr.keys, expr.values))
    if isinstance(expr, ast.BinOp):
        return _is_mapping(expr.left, names) or _is_mapping(expr.right, names)
    if isinstance(expr, ast.IfExp):
        return _is_mapping(expr.body, names) or _is_mapping(expr.orelse, names)
    if isinstance(expr, ast.BoolOp):
        return any(_is_mapping(v, names) for v in expr.values)
    if isinstance(expr, ast.NamedExpr):
        return _is_mapping(expr.value, names)
    return False


def _environment_names(tree):
    """Names bound from os.environ, resolved to a fixed point: the pinned parameters, every
    assignment target of a mapping expression, every `env=` keyword value and every parameter
    of a defined function that receives a mapping."""
    names = set(MATERIALISE_ENV_PARAMS)
    funcs = {n.name: n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
    changed = True
    while changed:
        before = len(names)
        for node in ast.walk(tree):
            pairs = []
            if isinstance(node, ast.Assign):
                pairs = [(t, node.value) for t in node.targets]
            elif isinstance(node, (ast.AnnAssign, ast.AugAssign)) and node.value is not None:
                pairs = [(node.target, node.value)]
            elif isinstance(node, ast.NamedExpr):
                pairs = [(node.target, node.value)]
            for target, value in pairs:
                if _is_mapping(value, names):
                    names.update(n.id for n in ast.walk(target) if isinstance(n, ast.Name))
            if isinstance(node, ast.keyword) and node.arg == "env" \
                    and isinstance(node.value, ast.Name):
                names.add(node.value.id)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                    and node.func.id in funcs:
                params = [a.arg for a in funcs[node.func.id].args.args]
                for index, arg in enumerate(node.args[:len(params)]):
                    if _is_mapping(arg, names):
                        names.add(params[index])
                for kw in node.keywords:
                    if kw.arg and _is_mapping(kw.value, names):
                        names.add(kw.arg)
        changed = len(names) != before
    return names


def _pinned_env_assigns(tree):
    """Assignment statements whose value is exactly the pinned environment construction."""
    return [n for n in ast.walk(tree)
            if isinstance(n, ast.Assign) and ast.unparse(n.value) == MATERIALISE_ENV_CONSTRUCTION]


def _env_use_ok(node, parents, pinned_call=None):
    """True when the reference is one of the read-only uses of an environment mapping, or the one
    pinned construction / pass-on."""
    parent = parents.get(node)
    if isinstance(parent, ast.Subscript):
        return parent.value is node and isinstance(parent.ctx, ast.Load)
    if isinstance(parent, ast.Attribute):
        call = parents.get(parent)
        return (parent.value is node and parent.attr in MATERIALISE_ENV_READS
                and isinstance(parent.ctx, ast.Load)
                and isinstance(call, ast.Call) and call.func is parent)
    if isinstance(parent, ast.Compare):
        return node in parent.comparators and all(
            isinstance(op, (ast.In, ast.NotIn)) for op in parent.ops)
    if isinstance(parent, ast.keyword):
        call = parents.get(parent)
        return parent.arg == "env" and isinstance(call, ast.Call) \
            and _chain(call.func) == "subprocess.run"
    if isinstance(parent, ast.Call):
        return parent is pinned_call or (
            ast.unparse(parent) == MATERIALISE_ENV_PASS_ON and parent.args[0] is node)
    return False


def _pinned_env_problems(label, tree, parents, pinned):
    """sec r11 S1: exactly one pinned construction bound to the one name in its function, every
    other mapping-valued expression refused, every env= keyword the pinned name."""
    problems = []
    scope = _scope_of(pinned[0], parents) if len(pinned) == 1 else None
    if not (len(pinned) == 1 and len(pinned[0].targets) == 1
            and isinstance(pinned[0].targets[0], ast.Name)
            and pinned[0].targets[0].id == MATERIALISE_ENV_NAME
            and scope is not None and scope.name == MATERIALISE_ENV_SCOPE):
        problems.append("%s: environment construction is not exactly one %s = %s in %s()"
                        % (label, MATERIALISE_ENV_NAME, MATERIALISE_ENV_CONSTRUCTION,
                           MATERIALISE_ENV_SCOPE))
    pinned_call = pinned[0].value if len(pinned) == 1 else None
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                and node.func.id == "dict" and node is not pinned_call:
            problems.append("%s: environment mapping built by dict() outside the pinned "
                            "construction" % label)
        elif isinstance(node, (ast.Dict, ast.DictComp)):
            problems.append("%s: environment mapping literal or comprehension outside the pinned "
                            "construction" % label)
        elif isinstance(node, ast.keyword) and node.arg == "env":
            call = parents.get(node)
            if not (isinstance(call, ast.Call) and _chain(call.func) == "subprocess.run"
                    and isinstance(node.value, ast.Name)
                    and node.value.id == MATERIALISE_ENV_NAME):
                problems.append("%s: environment keyword is not the pinned name %s on "
                                "subprocess.run" % (label, MATERIALISE_ENV_NAME))
        elif isinstance(node, ast.Call) and _chain(node.func) == "subprocess.run":
            keys = [k for k in node.keywords if k.arg == "env"]
            scope = _scope_of(node, parents)
            if len(keys) != 1 or scope is None or scope.name != MATERIALISE_ENV_SCOPE:
                problems.append("%s: environment of subprocess.run is not the pinned copy (one "
                                "env= keyword in %s())" % (label, MATERIALISE_ENV_SCOPE))
            else:
                problems.extend("%s: environment name %s: %s" % (label, MATERIALISE_ENV_NAME, why)
                                for why in _name_problems(tree, parents, scope,
                                                          MATERIALISE_ENV_NAME)[:1])
    return problems


def _environment_problems(label, tree, parents):
    """Positive rule (sec r11 S1): the child environment is the one pinned construction, bound
    once and passed unmodified; every other environment mapping is only read (subscript load,
    .get/.items/.keys/.values, `in`) or passed on as derive_base(os.environ)."""
    pinned = _pinned_env_assigns(tree)
    pinned_call = pinned[0].value if len(pinned) == 1 else None
    names = _environment_names(tree)
    problems = _pinned_env_problems(label, tree, parents, pinned)
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id in names:
            if isinstance(node.ctx, ast.Load):
                ok = _env_use_ok(node, parents, pinned_call)
            else:
                ok = (isinstance(node.ctx, ast.Store) and len(pinned) == 1
                      and parents.get(node) is pinned[0] and node in pinned[0].targets)
            if not ok:
                problems.append("%s: environment mapping %s used outside the read-only forms"
                                % (label, node.id))
        elif isinstance(node, ast.Attribute) and _chain(node) == "os.environ":
            if not _env_use_ok(node, parents, pinned_call):
                problems.append("%s: environment mapping os.environ used outside the read-only "
                                "forms" % label)
    return problems


def _definition_problems(label, tree):
    """sec r11 S3/S4: no decorator, class keyword, class base other than Exception, type
    parameter or type alias; each of them binds or calls without a Call or Name node the
    allow-list would see."""
    problems = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node.decorator_list:
                problems.append("%s: decorator on %s outside the allow-list" % (label, node.name))
            if getattr(node, "type_params", None):
                problems.append("%s: type parameters on %s outside the allow-list"
                                % (label, node.name))
        if isinstance(node, ast.ClassDef):
            if node.keywords:
                problems.append("%s: class keyword on %s outside the allow-list"
                                % (label, node.name))
            if [ast.unparse(b) for b in node.bases] != ["Exception"]:
                problems.append("%s: class base of %s is not exactly Exception"
                                % (label, node.name))
        if type(node).__name__ == "TypeAlias":
            problems.append("%s: type parameter or type alias statement outside the allow-list"
                            % label)
    return problems


def _call_args_text(node):
    """The arguments of a call as one text: positional unparsed, keywords as k=v (`**v` for **)."""
    parts = [ast.unparse(a) for a in node.args]
    parts += [("%s=%s" % (k.arg, ast.unparse(k.value))) if k.arg else "**" + ast.unparse(k.value)
              for k in node.keywords]
    return ", ".join(parts)


def _call_arg_problems(label, tree, parents, node, callee):
    """sec r11 S2/S5: the call takes one of the enumerated argument texts of its callee, and the
    names in the argument of a git value sink resolve by their binding."""
    kind = MATERIALISE_CALL_KINDS.get(callee)
    if _call_args_text(node) not in MATERIALISE_CALL_ARGS[callee]:
        if kind:
            return ["%s: %s outside the enumerated arguments" % (label, kind)]
        return ["%s: call argument is not enumerated for %s" % (label, callee)]
    problems = []
    if callee == "handle.write" and _call_args_text(node) == "line + '\\n'":
        stmt = parents.get(node)
        block = parents.get(stmt)
        guard = parents.get(block)
        scope = parents.get(guard)
        if not (isinstance(stmt, ast.Expr) and isinstance(block, ast.With) and block.body == [stmt]
                and isinstance(guard, ast.If) and ast.unparse(guard.test) == "summary"
                and not guard.orelse and guard.body == [block]
                and isinstance(scope, ast.FunctionDef) and scope.name == "report"
                and any(a is guard for a in scope.body)):
            problems.append("%s: summary write is not the sole body of `with open(summary)` under "
                            "`if summary:` directly in report()" % label)
    if callee in MATERIALISE_OUTPUT_SINKS:
        for arg in node.args:
            problems.extend(_value_name_problems(label, tree, parents, node, arg))
    return problems


def _guard_problems(label, tree):
    body = tree.body
    guards = [i for i, s in enumerate(body)
              if isinstance(s, ast.If) and ast.unparse(s.test) == MATERIALISE_GUARD_TEST]
    ok = (len(guards) == 1 and guards[0] == len(body) - 1 and not body[-1].orelse
          and [ast.unparse(s) for s in body[-1].body] == MATERIALISE_GUARD_BODY)
    return [] if ok else ["%s: statement outside the __main__ guard rule (the guard is last and "
                          "holds only sys.exit(main()))" % label]


def _argv_problems(label, node, tree, parents):
    argv = node.args[0] if node.args else None
    head = argv.left if isinstance(argv, ast.BinOp) and isinstance(argv.op, ast.Add) else None
    good = (isinstance(head, ast.List) and len(head.elts) == len(MATERIALISE_GIT_ARGV)
            and all(isinstance(e, ast.Constant) for e in head.elts)
            and tuple(e.value for e in head.elts) == MATERIALISE_GIT_ARGV
            and ast.unparse(argv.right) == MATERIALISE_RUN_ARGV_TAIL and len(node.args) == 1)
    problems = []
    if not good:
        problems.append("%s: subprocess.run argv is not the exact git head plus list(args)" % label)
    else:
        tail = argv.right.args[0] if isinstance(argv.right, ast.Call) and argv.right.args else None
        scope = _scope_of(node, parents)
        if not (isinstance(tail, ast.Name) and _param_ok(scope, tail.id)):
            problems.append("%s: argv tail is not list() of an unrebound parameter of its "
                            "function (exactly one binding)" % label)
    if {k.arg for k in node.keywords} - MATERIALISE_RUN_KEYWORDS or any(
            k.arg is None for k in node.keywords):
        problems.append("%s: subprocess.run keyword outside the allow-list" % label)
    return problems


def _git_call_problems(label, node, tree, parents):
    problems = []
    first = node.args[0] if node.args else None
    if not (isinstance(first, ast.Constant) and first.value in MATERIALISE_GIT_SUBCOMMANDS):
        problems.append("%s: git call with a subcommand outside the allow-list" % label)
    if node.keywords:
        problems.append("%s: git call with keyword arguments" % label)
    for arg in node.args:
        literal = isinstance(arg, ast.Constant) and isinstance(arg.value, str)
        if not literal and ast.unparse(arg) not in MATERIALISE_GIT_VALUE_ARGS:
            problems.append("%s: git argument is not a literal or a pinned expression" % label)
        elif not literal:
            problems.extend(_value_name_problems(label, tree, parents, node, arg))
    return problems


def _function_problems(label, tree):
    """code r13 F1 / sec r13 S1: every class and function of the heredoc is one of the pinned set,
    defined once at module level, and its normalised ast.dump equals the pinned one."""
    problems = []
    every = [n for n in ast.walk(tree)
             if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]
    for node in every:
        if node.name not in MATERIALISE_FUNCTION_DUMPS:
            problems.append("%s: function %s is not in the pinned function set" % (label, node.name))
    for name in sorted(MATERIALISE_FUNCTION_DUMPS):
        top = [n for n in tree.body if getattr(n, "name", None) == name]
        total = len([n for n in every if n.name == name])
        if not top:
            problems.append("%s: function %s is missing from the pinned function set"
                            % (label, name))
        elif len(top) != 1 or total != 1 or ast.dump(top[0]) != MATERIALISE_FUNCTION_DUMPS[name]:
            problems.append("%s: function %s differs from its pinned normalised ast.dump"
                            % (label, name))
    return problems


def _module_body_problems(label, tree):
    """sec r14 S1: the module body, with every class and function body elided, equals the pinned
    statement sequence (imports, constants, the 12 definitions in order, the guard)."""
    if _elided_module_dump(tree) == MATERIALISE_MODULE_DUMP:
        return []
    return ["%s: module body differs from its pinned statement sequence (function and class "
            "bodies elided)" % label]


def materialise_allow_list_problems(label, run):
    """Reasons the Materialise body reaches a call target, binding, environment write or argument
    outside the allow-list."""
    found = HEREDOC_RE.match(normalise_run(run or ""))
    if found is None:
        return ["%s: run text is not one bare python3 -I heredoc" % label]
    try:
        tree = ast.parse(found.group("body"))
    except SyntaxError:
        return ["%s: heredoc body is not valid python" % label]
    problems = _binding_problems(label, tree)
    problems.extend(_definition_problems(label, tree))
    problems.extend(_function_problems(label, tree))
    problems.extend(_module_body_problems(label, tree))
    parents = _parents(tree)
    for name, kind, site in _bound_names(tree):
        if kind == "store" and _scope_of(site, parents) is None \
                and not (name in MATERIALISE_MODULE_STORES
                         and isinstance(parents.get(site), ast.Assign)):
            problems.append("%s: module-level binding of %s outside the pinned module stores"
                            % (label, name))
    for name in sorted(MATERIALISE_CONST_BINDINGS):
        problems.extend("%s: %s" % (label, reason)
                        for reason in _name_problems(tree, parents, None, name))
    callees = {id(n.func) for n in ast.walk(tree) if isinstance(n, ast.Call)}
    receivers = {id(n.value) for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    except_types = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler) and node.type is not None:
            except_types.add(id(node.type))
            if isinstance(node.type, ast.Tuple):
                except_types.update(id(e) for e in node.type.elts)
    runs = 0
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) \
                and node.id in MATERIALISE_MODULE_ROOTS and id(node) not in receivers:
            problems.append("%s: bare reference to module %s" % (label, node.id))
        elif isinstance(node, ast.Attribute) and isinstance(node.ctx, (ast.Store, ast.Del)):
            problems.append("%s: assigns or deletes attribute .%s" % (label, node.attr))
        elif isinstance(node, ast.Subscript) and isinstance(node.ctx, (ast.Store, ast.Del)):
            problems.append("%s: stores into or deletes from %s (the body has no subscript store)"
                            % (label, _chain(node.value) or "a value"))
        elif isinstance(node, ast.Attribute) and id(node) not in callees \
                and id(node) not in receivers:
            chain = _chain(node)
            if (chain or "").split(".")[0] in MATERIALISE_MODULE_ROOTS and (
                    chain not in MATERIALISE_VALUE_CHAINS
                    or (chain == "subprocess.TimeoutExpired" and id(node) not in except_types)):
                problems.append("%s: reaches %s outside the allow-list (an allowed module chain "
                                "is accepted in call position only)" % (label, chain))
        if isinstance(node, ast.Call):
            func = node.func
            chain = _chain(func)
            if isinstance(func, ast.Name):
                if func.id not in MATERIALISE_NAME_CALLS:
                    problems.append("%s: calls %s outside the allow-list" % (label, func.id))
                if func.id == "git":
                    problems.extend(_git_call_problems(label, node, tree, parents))
                elif func.id in ("open", "Path"):
                    problems.extend(_open_path_problems(label, tree, parents, node, func.id))
            elif chain in MATERIALISE_ENVIRON_WRITERS:
                problems.append("%s: writes the process environment (%s)" % (label, chain))
            elif chain is None:
                problems.append("%s: call on an unenumerated receiver" % label)
            elif chain not in MATERIALISE_MODULE_CHAINS and chain not in MATERIALISE_METHOD_CHAINS:
                problems.append("%s: calls %s outside the allow-list" % (label, chain))
            else:
                problems.extend(_receiver_problems(label, tree, parents, node))
            if chain in MATERIALISE_CALL_ARGS:
                problems.extend(_call_arg_problems(label, tree, parents, node, chain))
            if chain == "subprocess.run":
                runs += 1
                problems.extend(_argv_problems(label, node, tree, parents))
        elif isinstance(node, ast.Lambda) or type(node).__name__ == "Match":
            problems.append("%s: %s statement outside the allow-list"
                            % (label, "match" if type(node).__name__ == "Match" else "lambda"))
        elif (isinstance(node, ast.Constant) and isinstance(node.value, str)
              and node.value.startswith("-") and node.value not in MATERIALISE_DASH_ARGS):
            problems.append("%s: dash argument outside the allow-list" % label)
    if runs != 1:
        problems.append("%s: %d subprocess.run calls, expected exactly 1" % (label, runs))
    problems.extend(_environment_problems(label, tree, parents))
    problems.extend(_guard_problems(label, tree))
    return problems


def normalise_run(text):
    """CRLF to LF, trailing blanks off every line, exactly one final newline."""
    lines = [line.rstrip() for line in text.replace("\r\n", "\n").split("\n")]
    return "\n".join(lines).rstrip("\n") + "\n"


def run_digest(text):
    return hashlib.sha256(normalise_run(text).encode("utf-8")).hexdigest()


def materialise_problems(label, run):
    """Reasons a Materialise `run:` text is not the pinned one; names the label and both
    hashes, never the block."""
    problems = []
    got = run_digest(run or "")
    if got != MATERIALISE_SHA256[label]:
        problems.append("%s: run text sha256 %s, expected %s"
                        % (label, got, MATERIALISE_SHA256[label]))
    found = HEREDOC_RE.match(normalise_run(run or ""))
    if found is None:
        problems.append("%s: run text is not one bare python3 -I heredoc" % label)
        return problems
    try:
        tree = ast.parse(found.group("body"))
    except SyntaxError:
        problems.append("%s: heredoc body is not valid python" % label)
        return problems
    problems.extend(materialise_allow_list_problems(label, run))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name not in MATERIALISE_IMPORTS:
                    problems.append("%s: imports %s" % (label, alias.name))
        elif isinstance(node, ast.ImportFrom):
            if node.module not in MATERIALISE_IMPORTS or node.level:
                problems.append("%s: imports from %s" % (label, node.module))
        elif isinstance(node, ast.Name) and node.id in MATERIALISE_REFUSED_NAMES:
            problems.append("%s: names %s" % (label, node.id))
        elif isinstance(node, ast.Attribute) and node.attr in MATERIALISE_REFUSED_ATTRS:
            problems.append("%s: names .%s" % (label, node.attr))
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            for word in node.value.split():
                if PATH_LIKE_RE.search(word) and word not in MATERIALISE_PATH_WORDS:
                    problems.append("%s: names a path outside the allow-list (%d chars)"
                                    % (label, len(word)))
    return problems


def _mapping(value, where, problems):
    if isinstance(value, dict):
        return value
    problems.append("%s is not a mapping" % where)
    return {}


def _defaults_problems(defaults, where):
    """Any workflow or job `defaults` is refused: it can set the shell and the cwd."""
    if defaults is None:
        return []
    found = ["%s sets defaults" % where]
    run = defaults.get("run") if isinstance(defaults, dict) else None
    if isinstance(run, dict):
        found.extend("%s sets defaults.run.%s" % (where, key) for key in sorted(run))
    return found


def _fold_name(value):
    """casefold, strip and collapse internal whitespace (sec r14 S2 / code r14 F1)."""
    return " ".join(value.casefold().split())


def _matrix_carries_key(definition, key):
    """sec r15 A: strategy.matrix is a mapping that holds `key` directly or in every entry of a
    non-empty `include` list; anything else (absent, a string expression, an empty include) is no."""
    strategy = definition.get("strategy")
    matrix = strategy.get("matrix") if isinstance(strategy, dict) else None
    if not isinstance(matrix, dict):
        return False
    if key in matrix:
        return True
    include = matrix.get("include")
    return (isinstance(include, list) and bool(include)
            and all(isinstance(entry, dict) and key in entry for entry in include))


def _job_id_problem(job, gate):
    """The job id of a job other than the gate folds to the gate check name (a nameless job, or a
    job whose name is null or empty, renders its id as the check context)."""
    if job != GATE_JOB and isinstance(job, str) and _fold_name(job) == gate:
        return "job %s defaults its check name to the gate check name" % job
    return None


def _job_name_problems(job, definition):
    """sec r14 S2 / code r14 F1, sec r15 A-B: no job other than the gate has the gate check name,
    whether spelled with another case, padding, or (when `name` is absent, empty or a YAML null
    spelling) its job id; a job display name is never an expression except the two pinned matrix
    names, each accepted only on its own job id while that job carries a strategy.matrix holding the
    key it renders; a null-spelled or empty name is refused outright. The rule is a text pin: the
    expressions are refused, never evaluated."""
    if not isinstance(definition, dict):
        return []
    problems = []
    gate = _fold_name(JOB_NAMES[GATE_JOB])
    if "name" not in definition:
        by_id = _job_id_problem(job, gate)
        return [by_id] if by_id else problems
    name = definition["name"]
    if not isinstance(name, str):
        return ["job %s name is not a string" % job]
    folded = _fold_name(name)
    if not folded or folded in NULL_SPELLINGS:
        problems.append("job %s has a null or empty name" % job)
        by_id = _job_id_problem(job, gate)
        if by_id:
            problems.append(by_id)
        return problems
    if "${{" in name:
        pinned = JOB_MATRIX_NAMES.get(job)
        if pinned is None or name != pinned[0]:
            problems.append("job %s name carries an expression outside the pinned set" % job)
        elif not _matrix_carries_key(definition, pinned[1]):
            problems.append("job %s name needs a strategy.matrix holding the key %s"
                            % (job, pinned[1]))
    if job != GATE_JOB and folded == gate:
        problems.append("job %s carries the gate check name %s" % (job, JOB_NAMES[GATE_JOB]))
    return problems


def pre_trust_problems(text):
    """Every reason the pre-trust steps of either job are off the allow-list; [] when clean.

    Reads the PARSED document (strict subset loader, fails closed) and judges the effective
    environment of each pre-trust step: workflow env, job env, step env, and the workflow,
    job and step shell / working-directory.
    """
    try:
        doc = yaml_subset_load(text)
    except YamlSubsetError as exc:
        return ["workflow is unreadable by the strict loader: %s" % exc]
    problems = []
    doc = _mapping(doc, "workflow", problems)
    workflow_env = _mapping(doc.get("env", {}), "workflow env", problems)
    problems.extend(_defaults_problems(doc.get("defaults"), "workflow"))
    for key in sorted(set(workflow_env) - WORKFLOW_ENV_ALLOW):
        problems.append("workflow env sets %s" % key)
    if workflow_env != WORKFLOW_ENV_VALUES:
        problems.append("workflow env differs from the pinned key/value mapping")
    if doc.get("permissions") != WORKFLOW_PERMISSIONS:
        problems.append("workflow permissions differ from the pinned mapping")
    jobs = _mapping(doc.get("jobs"), "jobs", problems)
    for other, other_def in sorted(jobs.items(), key=lambda item: str(item[0])):
        problems.extend(_job_name_problems(other, other_def))
    for job in (SELECT_JOB, GATE_JOB):
        allow, marker = WINDOWS[job]
        definition = _mapping(jobs.get(job), "job %s" % job, problems)
        if definition.get("name") != JOB_NAMES[job]:
            problems.append("job %s name %r, expected %r"
                            % (job, definition.get("name"), JOB_NAMES[job]))
        for key in JOB_KEYS_REFUSED:
            if key in definition:
                problems.append("job %s sets %s" % (job, key))
        problems.extend(_defaults_problems(definition.get("defaults"), "job %s" % job))
        if sorted(definition) != JOB_KEY_SETS[job]:
            problems.append("job %s keys %r, expected %r"
                            % (job, sorted(definition), JOB_KEY_SETS[job]))
        if definition.get("runs-on") != JOB_RUNS_ON:
            problems.append("job %s runs-on %r, expected %r"
                            % (job, definition.get("runs-on"), JOB_RUNS_ON))
        if definition.get("permissions") != JOB_PERMISSIONS:
            problems.append("job %s permissions %r, expected %r"
                            % (job, definition.get("permissions"), JOB_PERMISSIONS))
        job_env = _mapping(definition.get("env", {}), "job %s env" % job, problems)
        for key in sorted(set(job_env) - JOB_ENV_ALLOW[job]):
            problems.append("job %s env sets %s" % (job, key))
        if job_env != JOB_ENV_VALUES[job]:
            problems.append("job %s env differs from the pinned key/value mapping" % job)
        steps = definition.get("steps")
        if not isinstance(steps, list) or not all(isinstance(s, dict) for s in steps):
            problems.append("job %s steps are not a list of mappings" % job)
            continue
        names = [s.get("name") for s in steps]
        if marker not in names:
            problems.append("job %s has no step %r" % (job, marker))
            continue
        window = steps[:names.index(marker)]
        if [s.get("name") for s in window] != [entry[0] for entry in allow]:
            problems.append("job %s pre-trust steps are %r, expected %r"
                            % (job, [s.get("name") for s in window], [e[0] for e in allow]))
            continue
        for step, (name, keys, env_keys, with_map, run) in zip(window, allow):
            where = "job %s step %r" % (job, name)
            if set(step) != keys:
                problems.append("%s keys %r, expected %r" % (where, sorted(step), sorted(keys)))
            for key in STEP_KEYS_REFUSED:
                if key in step:
                    problems.append("%s sets %s" % (where, key))
            step_env = _mapping(step.get("env", {}), where + " env", problems)
            effective = dict(workflow_env)
            effective.update(job_env)
            effective.update(step_env)
            allowed_env = WORKFLOW_ENV_ALLOW | JOB_ENV_ALLOW[job] | env_keys
            for key in sorted(set(effective) - allowed_env):
                problems.append("%s inherits env %s" % (where, key))
            for key in sorted(effective):
                if FORBIDDEN_ENV_RE.match(key):
                    problems.append("%s inherits start-up env %s" % (where, key))
            if set(step_env) != env_keys:
                problems.append("%s env keys %r, expected %r"
                                % (where, sorted(step_env), sorted(env_keys)))
            if step_env != STEP_ENV_VALUES.get((job, name), {}):
                problems.append("%s env values differ from the pinned mapping" % where)
            if name is None:
                if step.get("uses") != CHECKOUT_ACTION:
                    problems.append("%s uses %r" % (where, step.get("uses")))
                if step.get("with") != with_map:
                    problems.append("%s with %r, expected %r" % (where, step.get("with"), with_map))
                continue
            if "uses" in step:
                problems.append("%s uses an action" % where)
            if with_map is not None and step.get("with") != with_map:
                problems.append("%s with differs" % where)
            if run is HEREDOC:
                problems.extend(materialise_problems(name, step.get("run")))
            elif step.get("run") != run:
                problems.append("%s run text differs from the allow-list" % where)
    return problems


class TrustDecisionFirst(unittest.TestCase):
    """S15: the trust decision runs before any checkout file executes.

    decision: the trust decision runs before any checkout file executes and the
    derivation is inline with no resolver script run over keeping a resolver
    step first because any PR-tree step that runs earlier in the job can rewrite
    the git state and PATH the derivation reads (the resolver is a library for
    its unit tests; no workflow step runs it)

    The base_sha.py resolver is wired into no step of either job: the inline
    derivation is the sole authority. The bootstrap fold and the branch-tip fold
    are the only steps that run a scripts/ci/ path from the checkout, and both
    run after the derivation (the branch-tip fold only on events with no live
    base).
    """

    JOBS = ((SELECT_JOB, MATERIALISE_STEP), (GATE_JOB, GATE_MATERIALISE_STEP))
    CHECKOUT = "actions/checkout@11d5960a326750d5838078e36cf38b85af677262"
    NAMED_EXCEPTIONS = (BOOTSTRAP_STEP, BRANCH_TIP_STEP)

    # F4 / S16 / F1-F3: the pre-trust window is an ALLOW-LIST judged on the PARSED document
    # (pre_trust_problems above): a `run:`, another `uses:`, a `shell:` or `working-directory:`
    # at the step, job or workflow level, and any env key the step inherits beyond the
    # allow-list is red until it is allow-listed.
    # decision: a YAML-parsed effective-environment allow-list and a content hash on the
    # Materialise block over a line-oriented text scan because the runner evaluates the
    # parsed document and inherited env, so a scanner that sees less than the runner fails open
    CHECKOUT_USES = CHECKOUT_ACTION
    GATE_ALLOW = GATE_ALLOW

    def parsed_steps(self, job):
        doc = yaml_subset_load(CI_YML.read_text())
        return doc["jobs"][job]["steps"]

    def window(self, job):
        steps = self.parsed_steps(job)
        names = [s.get("name") for s in steps]
        return steps[:names.index(WINDOWS[job][1])]

    def test_the_pre_trust_window_is_an_exact_allow_list_of_steps(self):
        """F1/F2: parsed steps, effective env, workflow and job defaults; [] problems."""
        self.assertEqual(pre_trust_problems(CI_YML.read_text()), [])
        for job in (SELECT_JOB, GATE_JOB):
            with self.subTest(job=job):
                self.assertEqual([s.get("name") for s in self.window(job)],
                                 [a[0] for a in WINDOWS[job][0]])

    def test_the_only_action_before_the_trust_decision_is_the_pinned_checkout(self):
        for job in (SELECT_JOB, GATE_JOB):
            uses = [s["uses"] for s in self.window(job) if "uses" in s]
            with self.subTest(job=job):
                self.assertEqual(uses, [self.CHECKOUT_USES])

    def test_no_job_level_override_can_alter_the_shell_or_the_start_up_env(self):
        """S16/F2: shell, working-directory, defaults and poisoned env at every scope."""
        doc = yaml_subset_load(CI_YML.read_text())
        self.assertNotIn("defaults", doc)
        self.assertEqual(set(doc.get("env", {})), WORKFLOW_ENV_ALLOW)
        for key in doc["env"]:
            self.assertIsNone(FORBIDDEN_ENV_RE.match(key), key)
        for job in (SELECT_JOB, GATE_JOB):
            definition = doc["jobs"][job]
            with self.subTest(job=job, scope="job"):
                for key in JOB_KEYS_REFUSED + ("defaults",):
                    self.assertNotIn(key, definition)
                self.assertEqual(set(definition.get("env", {})), JOB_ENV_ALLOW[job])
                for key in definition.get("env", {}):
                    self.assertIsNone(FORBIDDEN_ENV_RE.match(key), key)
            for step in definition["steps"]:
                with self.subTest(job=job, step=step.get("name")):
                    for key in STEP_KEYS_REFUSED:
                        self.assertNotIn(key, step)
                    for key in step.get("env", {}):
                        self.assertIsNone(FORBIDDEN_ENV_RE.match(key), key)

    def test_the_materialise_run_text_is_pinned_by_content(self):
        """F3: sha256 of the normalised run block; a failure names the label and both hashes."""
        for job, name in self.JOBS:
            with self.subTest(job=job):
                self.assertEqual(materialise_problems(name, step_named(job, name)["run"]), [])
                self.assertEqual(run_digest(step_named(job, name)["run"]),
                                 MATERIALISE_SHA256[name])

    def test_the_materialise_body_names_no_checkout_path_and_runs_no_checkout_file(self):
        """F3: no import beyond the stdlib set, no exec-like name, no path outside the list."""
        for job, name in self.JOBS:
            run = step_named(job, name)["run"]
            with self.subTest(job=job):
                self.assertEqual([p for p in materialise_problems(name, run)
                                  if "sha256" not in p], [])

    def mutated(self, job, old, new):
        """ci.yml text with the first `old` after the `  <job>:` header replaced by `new`."""
        body = CI_YML.read_text()
        start = body.index("\n  %s:\n" % job)
        at = body.index(old, start)
        return body[:at] + new + body[at + len(old):]

    F2_MUTANTS = (
        ("select step env value", SELECT_JOB, "CONTEXT_SHA: ${{ github.sha }}",
         "CONTEXT_SHA: ${{ github.ref }}"),
        ("gate step env value", GATE_JOB, "IMPACT_FILES: __init__.py common.py gate.py rules.json",
         "IMPACT_FILES: __init__.py common.py gate.py rules.json extra.py"),
        ("select mode env value", SELECT_JOB, "ENFORCE: ${{ vars.CI_IMPACT_ENFORCE }}",
         "ENFORCE: ${{ vars.OTHER }}"),
        ("gate fold env value", GATE_JOB, "GITHUB_REF_NAME_FULL: ${{ github.ref }}",
         "GITHUB_REF_NAME_FULL: refs/heads/main"),
        ("select job env value", SELECT_JOB, "RUSTUP_TOOLCHAIN: stable",
         "RUSTUP_TOOLCHAIN: nightly"),
        ("select job-level key", SELECT_JOB, "    timeout-minutes: 15\n",
         "    timeout-minutes: 15\n    continue-on-error: true\n"),
        ("gate job-level key", GATE_JOB, "    timeout-minutes: 5\n",
         "    timeout-minutes: 5\n    concurrency: x\n"),
        ("select runs-on self-hosted", SELECT_JOB, "    runs-on: ubuntu-latest\n",
         "    runs-on: [self-hosted, linux]\n"),
        ("gate runs-on self-hosted", GATE_JOB, "    runs-on: ubuntu-latest\n",
         "    runs-on: self-hosted\n"),
        ("select job permissions widened", SELECT_JOB, "    timeout-minutes: 15\n",
         "    timeout-minutes: 15\n    permissions:\n      contents: write\n"),
        ("gate job permissions widened", GATE_JOB, "    timeout-minutes: 5\n",
         "    timeout-minutes: 5\n    permissions: write-all\n"),
    )

    def test_f2_exact_env_values_job_keys_runs_on_and_permissions_are_pinned(self):
        """sec r8 F2: a changed pre-trust env VALUE, an extra job key, a self-hosted runs-on
        or a widened permissions block each make the allow-list red."""
        for label, job, old, new in self.F2_MUTANTS:
            with self.subTest(mutant=label):
                self.assertNotEqual(pre_trust_problems(self.mutated(job, old, new)), [])

    def test_code_r13_f2_both_jobs_timeout_minutes_are_pinned(self):
        """code r13 F2: the select job and the gate job each keep their timeout-minutes value
        (a longer gate timeout lets a hung base fold hold the required check open)."""
        jobs = yaml_subset_load(CI_YML.read_text())["jobs"]
        self.assertEqual({job: jobs[job].get("timeout-minutes") for job in JOB_TIMEOUT_MINUTES},
                         JOB_TIMEOUT_MINUTES)
        for job, minutes in JOB_TIMEOUT_MINUTES.items():
            with self.subTest(job=job):
                widened = CI_YML.read_text().replace(
                    "    timeout-minutes: %s\n" % minutes, "    timeout-minutes: 600\n", 1)
                self.assertNotEqual(widened, CI_YML.read_text())
                again = yaml_subset_load(widened)["jobs"]
                self.assertNotEqual(again[job].get("timeout-minutes"), minutes)

    def test_f2_workflow_permissions_are_pinned(self):
        body = CI_YML.read_text()
        old = "permissions:\n  contents: read\n"
        self.assertEqual(body.count("\n" + old), 1)
        widened = body.replace("\n" + old, "\npermissions:\n  contents: write\n")
        self.assertNotEqual(pre_trust_problems(widened), [])

    BANNED_PHRASE = "demoted to a post-" + "derivation report"

    def test_f1_no_post_derivation_report_wording_in_the_workflow_or_this_module(self):
        """sec r8 F1: no step runs the resolver after the derivation; the wording is gone."""
        flat = " ".join(CI_YML.read_text().split())
        self.assertNotIn(self.BANNED_PHRASE, flat)
        module = " ".join(Path(__file__).read_text().split())
        self.assertNotIn(self.BANNED_PHRASE, module)

    C2_MUTANT_ANCHOR = "GIT_TIMEOUT_S = 120\n"
    C2_MUTANTS = (
        ("sh-getoutput", 'subprocess.getoutput("make prep")'),
        ("sh-posix-spawnp", 'os.posix_spawnp("make", ["make"], dict(os.environ))'),
        ("sh-call-bare-file", 'subprocess.call(["sh", "prep.bash"])'),
        ("sh-git-alias", 'git("-c", "alias.p=!make", "p")'),
        ("sh-git-fsmonitor", 'git("-c", "core.fsmonitor=make", "status")'),
        ("sh-check-call", 'subprocess.check_call(["make", "prep"])'),
        ("sh-second-run", 'subprocess.run(["make", "prep"])'),
        ("sh-git-rebase-exec", 'git("rebase", "--exec", "make", "HEAD~1")'),
        ("sh-git-hookspath", 'git("status", "--config-env=core.hooksPath=H")'),
    )

    def test_code_c2_the_second_layer_is_an_allow_list_even_when_the_hash_is_rehashed(self):
        """code r8 C2: each non-git execution form is red with the sha256 pin rehashed to it."""
        for job, name in self.JOBS:
            run = step_named(job, name)["run"]
            self.assertIn(self.C2_MUTANT_ANCHOR, run)
            for label, line in self.C2_MUTANTS:
                mutated = run.replace(self.C2_MUTANT_ANCHOR,
                                      self.C2_MUTANT_ANCHOR + line + "\n", 1)
                with self.subTest(job=job, mutant=label):
                    with unittest.mock.patch.dict(MATERIALISE_SHA256,
                                                  {name: run_digest(mutated)}):
                        problems = materialise_problems(name, mutated)
                    self.assertFalse([p for p in problems if "sha256" in p], problems)
                    self.assertNotEqual(problems, [])

    def test_code_c2_the_real_body_passes_the_allow_list_alone(self):
        for job, name in self.JOBS:
            with self.subTest(job=job):
                run = step_named(job, name)["run"]
                self.assertEqual(materialise_allow_list_problems(name, run), [])

    # sec F1 / code C1-C3 (round 12): receiver, binding, environment and argv forms. Each row is
    # one module-level snippet inserted after the anchor; with the sha256 pin re-pinned to the
    # mutated body the second layer alone must report it (a problem line that is not the digest).
    C12_MUTANTS = (
        ("x-module-alias", 'm = subprocess\nm.getoutput("make prep")'),
        ("x-module-alias-run", 'm = subprocess\nm.run(["git", "--no-replace-objects"] + [])'),
        ("x-os-alias", 'o = os\no.posix_spawnp("make", ["make"], {})'),
        ("c2x-module-alias-call", 'sp = subprocess; sp.call(["sh", "prep.bash"])'),
        ("b1-import-rebinds-allowed-name", "from subprocess import getoutput as git"),
        ("b1-import-os-as-module-root", "import os as subprocess"),
        ("b1-from-os-system-as-name", "from os import system as git"),
        ("b2-rebound-module-receiver", "re = sys\nre.exit(0)"),
        ("x-assign-allowed-name", "open = print"),
        ("x-annassign-allowed-name", "git: int = 1"),
        ("x-augassign-module-root", "subprocess += 1"),
        ("x-with-as-allowed-name", 'with print("x") as git:\n    pass'),
        ("x-for-target-module-root", "for subprocess in ():\n    pass"),
        ("x-comprehension-allowed-name", "[len for len in ()]"),
        ("x-parameter-allowed-name", "def _f(open):\n    return open"),
        ("x-environ-store", 'os.environ["GIT_CONFIG_COUNT"] = "1"'),
        ("x-environ-del", 'del os.environ["PATH"]'),
        ("x-environ-update", 'os.environ.update({"A": "b"})'),
        ("x-environ-setdefault", 'os.environ.setdefault("A", "b")'),
        ("x-environ-putenv", 'os.putenv("A", "b")'),
        ("x-environ-unsetenv", 'os.unsetenv("A")'),
        ("x-environ-alias-store", 'e = os.environ\ne["A"] = "b"'),
        ("x-environ-attr-rebind", "os.environ = {}"),
        ("b3-non-literal-head-element", 'ARGV = ["git", GIT_TIMEOUT_S, "--no-replace-objects"]'),
        ("b3-short-head", 'ARGV = ["git"] + []'),
        ("b3-plus-joined-non-list", 'ARGV = "git" + "x"'),
        ("b5-sliced-dash-argument", 'git("show", "xx-c"[2:])'),
        ("b5-concat-dash-argument", 'git("show", "--upload" + "-pack=make")'),
        ("b5-joinedstr-dash-argument", 'git("show", f"{GIT_TIMEOUT_S}")'),
        ("x-str-method-dash", 'git("fetch", "xx-c".replace("xx", ""), "origin")'),
        ("x-str-join-dash", 'git("fetch", "".join(["-", "c"]), "origin")'),
        ("x-str-format-dash", 'git("fetch", "{}c".format("-"), "origin")'),
        ("x-path-method-open", 'Path("x.git").open("a")'),
        ("x-path-method-write", 'Path("x.git").write_text("a")'),
        ("x-method-on-call-result", 'dict().update({"a": "b"})'),
        ("x-call-on-subscript", 'dict()["a"]()'),
    )
    C12_ARGV_ROWS = {"b3-non-literal-head-element", "b3-short-head", "b3-plus-joined-non-list"}

    def _c12_body(self, run, label, line):
        if label in self.C12_ARGV_ROWS:
            argv = '["git", "--no-replace-objects"] + list(args)'
            head = {"b3-non-literal-head-element": '["git", GIT_TIMEOUT_S, "--no-replace-objects"]',
                    "b3-short-head": '["git"]',
                    "b3-plus-joined-non-list": '"git" + "--no-replace-objects"'}[label]
            self.assertIn(argv, run)
            return run.replace(argv, head + " + list(args)", 1)
        return run.replace(self.C2_MUTANT_ANCHOR, self.C2_MUTANT_ANCHOR + line + "\n", 1)

    def test_sec_f1_every_receiver_binding_environment_and_argv_form_is_red_when_rehashed(self):
        """sec F1 / code C1-C2: with the sha256 pin re-pinned to the mutated body, the second layer
        alone reports every form (rebound receiver, import rebinding, os.environ writes, a
        non-literal or short argv head, a computed dash argument)."""
        for job, name in self.JOBS:
            run = step_named(job, name)["run"]
            for label, line in self.C12_MUTANTS:
                mutated = self._c12_body(run, label, line)
                with self.subTest(job=job, mutant=label):
                    self.assertNotEqual(mutated, run)
                    with unittest.mock.patch.dict(MATERIALISE_SHA256,
                                                  {name: run_digest(mutated)}):
                        problems = materialise_problems(name, mutated)
                    self.assertFalse([p for p in problems if "sha256" in p], problems)
                    self.assertNotEqual(problems, [])
                    self.assertNotEqual(materialise_allow_list_problems(name, mutated), [])

    def test_sec_f1_the_allow_list_constants_are_named_and_sorted(self):
        for const in (MATERIALISE_IMPORT_STATEMENTS, MATERIALISE_METHOD_CHAINS,
                      MATERIALISE_DEFINED_NAMES, MATERIALISE_GIT_VALUE_ARGS,
                      MATERIALISE_ENVIRON_WRITERS):
            self.assertEqual(list(const), sorted(const))
            self.assertEqual(len(const), len(set(const)))

    def test_code_c3_the_comment_states_what_the_allow_list_enforces_and_no_more(self):
        """code C3: the claim that the layer admits no -c, alias, fsmonitor, hooksPath or exec
        option holds for literal arguments only; the comment now lists what is enforced."""
        text = Path(__file__).read_text()
        claim = "no `-c`, no alias, fsmonitor, hooksPath" + " or exec option"
        self.assertNotIn(claim, " ".join(text.replace("#", " ").split()))
        start = text.index("# sec F1 / code C1-C3 (round 12)")
        block = text[start:text.index("MATERIALISE_MODULE_ROOTS =", start)]
        for phrase in MATERIALISE_ENFORCES:
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, " ".join(block.replace("#", " ").split()))

    # code r10 C1-C4 (round 13): environment mappings, match bindings, argv tail and value names
    # resolved by binding, open/Path arguments, the __main__ guard. Each row is
    # (label, anchor, inserted text, needle); the text is inserted straight after the anchor (the
    # module anchor when it is None); with the sha256 pin re-pinned the second layer alone must
    # report a problem line holding the needle.
    C13_GUARD = "    sys.exit(main())\n"
    C13_ENV_LINE = 'env = dict(os.environ, GIT_NO_REPLACE_OBJECTS="1")\n'
    C13_ENV = "environment mapping"
    C13_MUTANTS = (
        ("c1-child-env-store", C13_ENV_LINE, '    env["GIT_CONFIG_COUNT"] = "1"\n', C13_ENV),
        ("c1-child-env-update", C13_ENV_LINE, '    env.update({"A": "b"})\n', C13_ENV),
        ("c1-child-env-pop", C13_ENV_LINE, '    env.pop("PATH")\n', C13_ENV),
        ("c1-child-env-setdefault", C13_ENV_LINE, '    env.setdefault("A", "b")\n', C13_ENV),
        ("c1-child-env-clear", C13_ENV_LINE, "    env.clear()\n", C13_ENV),
        ("c1-child-env-augassign", C13_ENV_LINE, '    env |= {"A": "b"}\n', C13_ENV),
        ("c1-child-env-del", C13_ENV_LINE, '    del env["A"]\n', C13_ENV),
        ("c1-child-env-alias-store", C13_ENV_LINE, '    child = env\n    child["A"] = "b"\n',
         C13_ENV),
        ("c1-child-env-passed-on", C13_ENV_LINE, '    report(env, "x")\n', C13_ENV),
        ("c1-param-env-store", "def derive_base(env):\n", '    env["GIT_DIR"] = "x"\n', C13_ENV),
        ("c1-param-env-update", "def derive_base(env):\n", '    env.update({"A": "b"})\n',
         C13_ENV),
        ("c1-dict-copy-store-then-pass", None,
         'cenv = dict(os.environ)\ncenv["A"] = "b"\nderive_base(cenv)', C13_ENV),
        ("c1-dict-copy-alias-update", None,
         'cenv = dict(os.environ)\nalias = cenv\nalias.update({})', C13_ENV),
        ("c1-environ-copy-store", None, 'cenv = os.environ.copy()\ncenv["A"] = "b"', C13_ENV),
        ("c1-walrus-env-copy", None, '(cenv := dict(os.environ))\ncenv["A"] = "b"', C13_ENV),
        ("c2-match-capture-module", None, "match 1:\n    case subprocess:\n        pass",
         "match statement"),
        ("c2-match-star", None, "match [1]:\n    case [run, *rest]:\n        pass",
         "match statement"),
        ("c2-match-mapping-rest", None, "match {}:\n    case {**os}:\n        pass",
         "match statement"),
        ("c2-match-as", None, "match 1:\n    case x as run:\n        pass", "match statement"),
        ("c2-match-allowed-name", None, "match 1:\n    case git:\n        pass",
         "match statement"),
        ("c2-match-class-keyword", None, "match 1:\n    case dict(a=open):\n        pass",
         "match statement"),
        ("c3-args-assign", C13_ENV_LINE, '    args = ("show", "HEAD")\n', "argv tail"),
        ("c3-args-augassign", C13_ENV_LINE, '    args += ("show",)\n', "argv tail"),
        ("c3-args-annassign", C13_ENV_LINE, '    args: tuple = ("show",)\n', "argv tail"),
        ("c3-args-walrus", C13_ENV_LINE, '    (args := ("show",))\n', "argv tail"),
        ("c3-args-for-target", C13_ENV_LINE, '    for args in (("show",),):\n        pass\n',
         "argv tail"),
        ("c3-args-with-target", C13_ENV_LINE, "    with print() as args:\n        pass\n",
         "argv tail"),
        ("c3-args-comprehension", C13_ENV_LINE, "    [0 for args in ()]\n", "argv tail"),
        ("c3-args-match", C13_ENV_LINE, "    match 1:\n        case args:\n            pass\n",
         "argv tail"),
        ("c3-value-reassign", "def rev_parse(spec):\n", '    spec = "HEAD"\n', "git value name"),
        ("c3-value-augassign", "def rev_parse(spec):\n", '    spec += "x"\n', "git value name"),
        ("c3-value-walrus", "def rev_parse(spec):\n", '    (spec := "HEAD")\n',
         "git value name"),
        ("c3-base-reassign", "def have_commit(base):\n", '    base = "HEAD"\n', "git value name"),
        ("c3-path-reassign", "path = IMPACT_PREFIX + name\n", '    path = "x"\n',
         "git value name"),
        ("c3-rel-reassign", 'for rel in ("info/grafts", "shallow", "objects/info/alternates"):\n',
         '        rel = "x"\n', "git value name"),
        ("c3-prefix-reassign", None, 'IMPACT_PREFIX = "other/"', "git value name"),
        ("c4-open-unpinned-path", None, 'open("x.git", "a")', "open call"),
        ("c4-open-write-mode", None, 'open(os.environ["GITHUB_OUTPUT"], "w")', "open call"),
        ("c4-path-unpinned", None, 'Path(os.environ["HOME"])', "Path call"),
        ("c4-statement-after-guard", C13_GUARD, 'print("after")\n', "__main__ guard"),
        ("c4-statement-inside-guard", 'if __name__ == "__main__":\n', '    print("in")\n',
         "__main__ guard"),
    )

    def test_code_r10_every_environment_match_binding_argv_open_and_guard_form_is_red(self):
        """code r10 C1-C4: with the pin re-pinned to the mutated body, the second layer alone
        reports every form, naming the rule that caught it."""
        for job, name in self.JOBS:
            run = step_named(job, name)["run"]
            for label, anchor, text, needle in self.C13_MUTANTS:
                anchor = anchor or self.C2_MUTANT_ANCHOR
                text = text if text.endswith("\n") else text + "\n"
                mutated = run.replace(anchor, anchor + text, 1)
                with self.subTest(job=job, mutant=label):
                    self.assertIn(anchor, run)
                    self.assertNotEqual(mutated, run)
                    with unittest.mock.patch.dict(MATERIALISE_SHA256,
                                                  {name: run_digest(mutated)}):
                        problems = materialise_problems(name, mutated)
                    self.assertFalse([p for p in problems if "sha256" in p], problems)
                    found = materialise_allow_list_problems(name, mutated)
                    self.assertTrue([p for p in found if needle in p], (needle, found))

    # sec r10 S1-S3 (round 13): an allowed module chain only in call position, method receiver
    # names resolved by their binding, the heredoc body ends at the FIRST terminator line.
    S_REC = "method receiver name"
    C14_MUTANTS = (
        ("s1-chain-as-keyword-opener", None, "open('true', opener=subprocess.run)",
         "reaches subprocess.run"),
        ("s1-chain-as-keyword", None, "print(key=shutil.rmtree)", "reaches shutil.rmtree"),
        ("s1-chain-as-argument", None, "print(subprocess.run)", "reaches subprocess.run"),
        ("s1-chain-as-argument-sys-exit", None, "list(sys.exit)", "reaches sys.exit"),
        ("s1-chain-assigned-value", None, "_f = os.path.lexists", "reaches os.path.lexists"),
        ("s1-exception-chain-outside-except", None, "dict(a=subprocess.TimeoutExpired)",
         "reaches subprocess.TimeoutExpired"),
        ("s2-module-receiver-rebound", None, "handle = open('X', 'a')\nhandle.write('X')", S_REC),
        ("s2-handle-rebound-in-report", "def report(ok, reason, bootstrap=False):\n",
         '    handle = open(os.environ["GITHUB_OUTPUT"], "a")\n', S_REC),
        ("s2-env-rebound-in-derive-base", "def derive_base(env):\n", "    env = dict()\n", S_REC),
        ("s2-dest-rebound-in-materialise", "def materialise(base, dest, names):\n",
         '    dest = Path("x")\n', S_REC),
        ("s2-res-rebound-in-rev-parse", "def rev_parse(spec):\n", '    res = git("show", spec)\n',
         S_REC),
        ("s2-tree-rebound-in-fetch-blob", "def fetch_blob(base, name):\n", "    tree = base\n",
         S_REC),
        ("s2-listed-rebound-in-replace-refs", "def replace_refs_present():\n", "    listed = 1\n",
         S_REC),
        ("s2-target-rebound-in-materialise", "def materialise(base, dest, names):\n",
         "    target = dest\n", S_REC),
        ("s2-sha-re-rebound", None, "SHA_RE = 1", S_REC),
        ("s2-name-rebound-in-materialise", "def materialise(base, dest, names):\n",
         '    name = "x"\n', S_REC),
        ("s3-inner-terminator-line", None, "PY\ntrue", "heredoc"),
        ("s3-inner-terminator-then-command", None, "PY\nmake prep\ncat <<'PY'", "heredoc"),
    )

    def _check_rows(self, rows):
        for job, name in self.JOBS:
            run = step_named(job, name)["run"]
            for label, anchor, text, needle in rows:
                anchor = anchor or self.C2_MUTANT_ANCHOR
                text = text if text.endswith("\n") else text + "\n"
                mutated = run.replace(anchor, anchor + text, 1)
                with self.subTest(job=job, mutant=label):
                    self.assertIn(anchor, run)
                    self.assertNotEqual(mutated, run)
                    with unittest.mock.patch.dict(MATERIALISE_SHA256,
                                                  {name: run_digest(mutated)}):
                        problems = materialise_problems(name, mutated)
                    self.assertFalse([p for p in problems if "sha256" in p], problems)
                    found = materialise_allow_list_problems(name, mutated)
                    self.assertTrue([p for p in found if needle in p], (needle, found))

    def test_sec_r10_chain_receiver_and_heredoc_forms_are_red_when_rehashed(self):
        """sec r10 S1-S3: each probe form, rebuilt as a mutant row, is red from the second layer."""
        self._check_rows(self.C14_MUTANTS)

    # sec r11 S1-S5 (round 14): one pinned environment construction, enumerated value and call
    # arguments, no type parameters, no decorators or class keywords, enumerated rmtree and print
    # arguments, no parameter defaults as value bindings. Each row is (label, old, new, needle);
    # `old` is replaced by `new` once; with the sha256 pin re-pinned the second layer alone must
    # report a problem line holding the needle.
    R14_ENVL = '    env = dict(os.environ, GIT_NO_REPLACE_OBJECTS="1")\n'
    R14_RUNENV = "                              env=env)\n"
    R14_DERIVED = "        derived = derive_base(os.environ)\n"
    R14_HAVE = '    return git("cat-file", "-e", base + "^{commit}").returncode == 0\n'
    R14_SHOWBLOB = '    blob = git("show", "%s:%s" % (base, path))\n'
    R14_PRINT_OK = '        print("impact: selector files loaded from the base sha")\n'
    R14_RMTREE = "        shutil.rmtree(str(dest))\n"
    R14_CLASS = "class BaseUnavailable(Exception):\n"
    R14_TP = "type parameter" if sys.version_info >= (3, 12) else "not valid python"
    R14_DASH_FORMS = (
        ("chr", "chr(45) + 'c'"), ("percent-c", "'%c' % 45"),
        ("str-bytes", "str(b'-', 'ascii')"), ("dash-join", "'-'.join(['', 'c'])"),
        ("replace", "'x'.replace('x', '-')"), ("str-int", "str(-1)[0] * 2 + 'inert'"),
        ("fstring", "f'{chr(45)}c'"), ("slice", "'xx-c'[2:]"))
    R14_MUTANTS = (
        # S1: the one pinned environment construction
        ("s1-env-kw-PATH", R14_ENVL,
         '    env = dict(os.environ, GIT_NO_REPLACE_OBJECTS="1", PATH="inert")\n', "environment"),
        ("s1-env-kw-GIT_EXEC_PATH", R14_ENVL,
         '    env = dict(os.environ, GIT_NO_REPLACE_OBJECTS="1", GIT_EXEC_PATH="inert")\n',
         "environment"),
        ("s1-env-kw-GIT_CONFIG", R14_ENVL,
         '    env = dict(os.environ, GIT_NO_REPLACE_OBJECTS="1", GIT_CONFIG_COUNT="1", '
         'GIT_CONFIG_KEY_0="core.hooksPath", GIT_CONFIG_VALUE_0="inert")\n', "environment"),
        ("s1-env-drop-noreplace", R14_ENVL, "    env = dict(os.environ)\n", "environment"),
        ("s1-env-wrong-value", R14_ENVL,
         '    env = dict(os.environ, GIT_NO_REPLACE_OBJECTS="0")\n', "environment"),
        ("s1-env-starstar-literal", R14_ENVL,
         '    env = dict(os.environ, **{"GIT_NO_REPLACE_OBJECTS": "1", "PATH": "inert"})\n',
         "environment"),
        ("s1-env-starred-positional", R14_ENVL,
         '    env = dict(*[os.environ], GIT_NO_REPLACE_OBJECTS="1")\n', "environment"),
        ("s1-env-dict-of-dict", R14_ENVL,
         '    env = dict(dict(os.environ, GIT_NO_REPLACE_OBJECTS="1"), PATH="inert")\n',
         "environment"),
        ("s1-env-two-step-copy", R14_ENVL,
         '    base_env = dict(os.environ, GIT_NO_REPLACE_OBJECTS="1")\n'
         '    env = dict(base_env, PATH="inert")\n', "environment"),
        ("s1-env-recopy-PATH-prefix", R14_ENVL,
         R14_ENVL + '    env = dict(env, PATH="inert:" + os.environ["PATH"])\n', "environment"),
        ("s1-env-recopy-GIT_CONFIG", R14_ENVL,
         R14_ENVL + '    env = dict(env, GIT_CONFIG_COUNT="1", GIT_CONFIG_KEY_0="core.hooksPath", '
         'GIT_CONFIG_VALUE_0="inert")\n', "environment"),
        ("s1-env-literal-assigned", R14_ENVL, '    env = {"PATH": "inert"}\n', "environment"),
        ("s1-env-dict-comprehension", R14_ENVL,
         "    env = {k: v for k, v in os.environ.items()}\n", "environment"),
        ("s1-env-union-literal", R14_ENVL,
         '    env = dict(os.environ, GIT_NO_REPLACE_OBJECTS="1") | {"PATH": "inert"}\n',
         "environment"),
        ("s1-env-copy-of-copy", R14_ENVL, "    env = os.environ.copy().copy()\n", "environment"),
        ("s1-env-literal-in-run", R14_RUNENV, '                              env={"PATH": "inert"})\n',
         "environment"),
        ("s1-env-dict-call-in-run", R14_RUNENV, '                              env=dict(PATH="inert"))\n',
         "environment"),
        ("s1-env-none-in-run", R14_RUNENV, "                              env=None)\n", "environment"),
        ("s1-env-os-environ-in-run", R14_RUNENV, "                              env=os.environ)\n",
         "environment"),
        ("s1-env-function-result-in-run", R14_RUNENV,
         '                              env=(lambda: {"PATH": "inert"})())\n', "environment"),
        ("s1-env-missing-in-run", "timeout=GIT_TIMEOUT_S,\n" + R14_RUNENV,
         "timeout=GIT_TIMEOUT_S)\n", "environment"),
        ("s1-env-alias-then-run", R14_ENVL, R14_ENVL + "    other = env\n", "environment"),
        ("s1-env-second-pinned-copy", R14_ENVL,
         R14_ENVL + '    spare = dict(os.environ, GIT_NO_REPLACE_OBJECTS="1")\n', "environment"),
        ("s1-env-renamed", R14_ENVL,
         '    penv = dict(os.environ, GIT_NO_REPLACE_OBJECTS="1")\n', "environment"),
        ("s1-derive-base-dict-copy", R14_DERIVED,
         "        derived = derive_base(dict(os.environ))\n", "environment"),
        ("s1-derive-base-keyword", R14_DERIVED,
         "        derived = derive_base(env=os.environ)\n", "environment"),
        ("s1-derive-base-extra-arg", R14_DERIVED,
         "        derived = derive_base(os.environ, 1)\n", "environment"),
        ("s1-environ-alias-assign", "def main():\n", "def main():\n    alias = os.environ\n",
         "environment"),
        # S2: value arguments only from enumerated bindings
        ("s2-str-bytes-at-have-commit", R14_HAVE,
         R14_HAVE.rstrip("\n") + " or have_commit(str(b'-', 'ascii'))\n", "argument is not"),
        ("s2-chr-at-fetch-blob", "            blob = fetch_blob(base, name)\n",
         "            blob = fetch_blob(base, chr(45) + 'c')\n", "argument is not"),
        ("s2-chr-at-materialise", "        materialise(derived, dest, names)\n",
         "        materialise(chr(45) + 'c', dest, names)\n", "argument is not"),
        ("s2-chr-at-gate-absent", "        report(False, str(exc), gate_absent(derived))\n",
         "        report(False, str(exc), gate_absent(chr(45) + 'c'))\n", "argument is not"),
        ("s2-literal-dash-at-rev-parse", R14_DERIVED, R14_DERIVED + "        rev_parse('-c')\n",
         "argument is not"),
        ("s2-unlisted-literal-at-rev-parse", R14_DERIVED,
         R14_DERIVED + "        rev_parse('main')\n", "argument is not"),
        ("s2-keyword-at-rev-parse", R14_DERIVED,
         R14_DERIVED + "        rev_parse(spec=derived)\n", "argument is not"),
        ("s2-starred-at-rev-parse", R14_DERIVED, R14_DERIVED + "        rev_parse(*names)\n",
         "argument is not"),
        # S3: type parameters and type aliases (3.12)
        ("s3-def-type-param-subprocess", "def git(*args):\n", "def git[subprocess](*args):\n",
         R14_TP),
        ("s3-def-type-param-git", "def main():\n", "def main[git]():\n", R14_TP),
        ("s3-async-def-type-param", "def main():\n", "async def main[os]():\n", R14_TP),
        ("s3-class-type-param", R14_CLASS, "class BaseUnavailable[os](Exception):\n", R14_TP),
        ("s3-type-alias-os", "GIT_TIMEOUT_S = 120\n", "GIT_TIMEOUT_S = 120\ntype os = int\n",
         R14_TP),
        ("s3-type-alias-other", "GIT_TIMEOUT_S = 120\n",
         "GIT_TIMEOUT_S = 120\ntype Other = int\n", R14_TP),
        # S4: decorators and class keywords call without a Call node
        ("s4-decorator-print", "def main():\n", "@print\ndef main():\n", "decorator"),
        ("s4-decorator-git", "def main():\n", "@git\ndef main():\n", "decorator"),
        ("s4-decorator-call", "def main():\n", "@print()\ndef main():\n", "decorator"),
        ("s4-decorator-attribute", "def main():\n", "@os.fspath\ndef main():\n", "decorator"),
        ("s4-decorator-subscript", "def main():\n", "@[print][0]\ndef main():\n", "decorator"),
        ("s4-decorator-on-class", R14_CLASS, "@print\n" + R14_CLASS, "decorator"),
        ("s4-class-metaclass-print", R14_CLASS,
         "class BaseUnavailable(Exception, metaclass=print):\n", "class keyword"),
        ("s4-class-keyword-any", R14_CLASS, "class BaseUnavailable(Exception, flag=1):\n",
         "class keyword"),
        ("s4-class-keyword-starstar", R14_CLASS, "class BaseUnavailable(Exception, **{}):\n",
         "class keyword"),
        ("s4-class-base-print", R14_CLASS, "class BaseUnavailable(print):\n", "class base"),
        ("s4-class-base-extra", R14_CLASS, "class BaseUnavailable(Exception, OSError):\n",
         "class base"),
        # S5: shutil.rmtree and print arguments enumerated, no parameter defaults as bindings
        ("s5-rmtree-env-target", R14_RMTREE, '        shutil.rmtree(os.environ["HOME"])\n',
         "rmtree call"),
        ("s5-rmtree-bare-dest", R14_RMTREE, "        shutil.rmtree(dest)\n", "rmtree call"),
        ("s5-rmtree-literal", R14_RMTREE, "        shutil.rmtree('x')\n", "rmtree call"),
        ("s5-rmtree-other-name", R14_RMTREE, "        shutil.rmtree(str(target))\n",
         "rmtree call"),
        ("s5-rmtree-onerror", R14_RMTREE, "        shutil.rmtree(str(dest), onerror=print)\n",
         "rmtree call"),
        ("s5-rmtree-ignore-errors-false", "shutil.rmtree(str(dest), ignore_errors=True)\n",
         "shutil.rmtree(str(dest), ignore_errors=False)\n", "rmtree call"),
        ("s5-rmtree-dir-fd", R14_RMTREE, "        shutil.rmtree(str(dest), dir_fd=1)\n",
         "rmtree call"),
        ("s5-print-file-kw", R14_PRINT_OK,
         '        print("impact: selector files loaded from the base sha", file=handle)\n',
         "print call"),
        ("s5-print-sep-kw", R14_PRINT_OK,
         '        print("impact: selector files loaded from the base sha", sep="x")\n',
         "print call"),
        ("s5-print-starred", R14_PRINT_OK, "        print(*[1])\n", "print call"),
        ("s5-print-new-literal", R14_PRINT_OK, '        print("other")\n', "print call"),
        ("s5-print-env-value", "    print(line)\n", '    print(line, os.environ.get("HOME"))\n',
         "print call"),
        ("s5-default-rev-parse-spec", "def rev_parse(spec):\n", "def rev_parse(spec='HEAD'):\n",
         "default"),
        ("s5-default-have-commit-base", "def have_commit(base):\n",
         "def have_commit(base='HEAD'):\n", "default"),
        ("s5-default-fetch-blob-name", "def fetch_blob(base, name):\n",
         "def fetch_blob(base, name='x'):\n", "default"),
        ("s5-default-gate-absent-base", "def gate_absent(base):\n", "def gate_absent(base=None):\n",
         "default"),
        ("s5-kwonly-default-materialise", "def materialise(base, dest, names):\n",
         "def materialise(base, dest, *, names=()):\n", "default"),
        ("s5-default-derive-base-env", "def derive_base(env):\n", "def derive_base(env=None):\n",
         "default"),
    )

    def _check_replace_rows(self, rows):
        for job, name in self.JOBS:
            run = step_named(job, name)["run"]
            for label, old, new, needle in rows:
                olds = old if isinstance(old, tuple) else (old,)
                news = new if isinstance(new, tuple) else (new,)
                mutated = run
                for one_old, one_new in zip(olds, news):
                    mutated = mutated.replace(one_old, one_new, 1)
                with self.subTest(job=job, mutant=label):
                    for one_old in olds:
                        self.assertIn(one_old, run)
                    self.assertNotEqual(mutated, run)
                    with unittest.mock.patch.dict(MATERIALISE_SHA256,
                                                  {name: run_digest(mutated)}):
                        problems = materialise_problems(name, mutated)
                    self.assertFalse([p for p in problems if "sha256" in p], problems)
                    found = materialise_allow_list_problems(name, mutated)
                    self.assertTrue([p for p in found if needle in p], (needle, found))

    def test_sec_r11_every_environment_dash_typeparam_decorator_and_argument_form_is_red(self):
        """sec r11 S1-S5: each probe form, rebuilt as a mutant row, is red from the second layer
        with the pin re-pinned, naming the rule that caught it."""
        self._check_replace_rows(self.R14_MUTANTS + self.R14_DASH_ROWS
                                 + self.R14_CODE_ROWS)

    def test_code_r12_c2_the_round_13_regression_rows_are_red_with_their_own_rule(self):
        """code r12 C2: the 35 code r11 forms a round-13 rule already refuses stay as a named
        regression table; each carries the needle of the rule that refuses it."""
        self.assertEqual(len(self.R13_REGRESSION_ROWS), 35)
        self.assertEqual(len(self.R14_CODE_ROWS), 12)
        self._check_replace_rows(self.R13_REGRESSION_ROWS)

    def test_code_r12_c1_each_pinned_module_name_has_one_direct_binding_of_its_value(self):
        """code r12 C1: a second assignment, a changed value, a multi-target assignment and an
        assignment under if, try or while are all refused for every pinned module-level name."""
        self._check_replace_rows(self.R15_C1_ROWS)

    def test_sec_r12_report_writes_and_the_names_in_them_are_pinned(self):
        """sec r12 R1/R2: a re-pinned edit of the step output writes, of ok, reason, bootstrap or
        of line (runner-conditioned forms included) is refused by the second layer alone."""
        self._check_replace_rows(self.R15_SEC_ROWS)

    def test_code_r13_f1_f3_sec_r13_s1_the_control_flow_of_every_local_function_is_pinned(self):
        """code r13 F1/F3, sec r13 S1: a re-pinned runner-conditioned or unconditional edit of the
        control flow of any local function (gate_absent, derive_base, main) and of the shape of
        the `line` augmentation and the summary write is refused by the second layer alone."""
        self.assertEqual(len(self.R16_CODE_ROWS), 17)
        self._check_replace_rows(self.R16_CODE_ROWS)

    def test_sec_r14_s1_the_module_body_outside_the_pinned_functions_is_pinned(self):
        """sec r14 S1: a re-pinned statement at module level (before, between or after the defs,
        a duplicated or second guard, a moved import, an exec, a try around main) is refused by
        the module-body pin alone; the 8 reviewer forms and 7 placement forms are all red."""
        self.assertEqual(len(self.R17_MODULE_ROWS), 15)
        self._check_replace_rows(self.R17_MODULE_ROWS)

    def test_code_r13_f1_the_two_regression_pins_stay_red_with_their_earlier_rule(self):
        """code r13 F1: a gate_absent defined twice and a lambda rebinding of it are refused by
        the earlier rules at d883f264c; they stay as declared regression pins."""
        self.assertEqual(len(self.R16_REGRESSION_ROWS), 2)
        self._check_replace_rows(self.R16_REGRESSION_ROWS)

    def test_code_r13_f5_both_base_red_rows_of_round_15_are_declared_regression_pins(self):
        """code r13 F5 / sec r13 S3: the two R15_SEC_ROWS that 02c1ac64a already refused are
        named, so the table comment and the PR body cannot drift from the table."""
        self.assertEqual(self.R15_REGRESSION_PINS,
                         ("r2-print-other-name", "r1-report-call-forged-bootstrap"))
        labels = {row[0] for row in self.R15_SEC_ROWS}
        self.assertTrue(set(self.R15_REGRESSION_PINS) <= labels)

    def test_sec_r13_s1_the_function_pins_name_every_local_function_of_the_heredoc(self):
        """sec r13 S1: the pinned set is exactly the defined names the allow-list names, and each
        pinned text parses to the one def of that name."""
        pins = getattr(sys.modules[__name__], "MATERIALISE_FUNCTION_PINS", None)
        self.assertIsNotNone(pins)
        self.assertEqual(sorted(pins), MATERIALISE_DEFINED_NAMES)
        for name, text in pins.items():
            node = ast.parse(text).body[0]
            self.assertEqual(node.name, name)
        for job, name in self.JOBS:
            self.assertEqual(materialise_allow_list_problems(name, step_named(job, name)["run"]),
                             [])

    def test_code_r12_c2_no_row_in_any_table_has_an_empty_needle(self):
        """code r12 C2: every row names the rule that refuses it; an empty needle guards nothing.
        The checker itself is shown to flag a planted empty row."""
        planted = (("planted-empty", "a", "b", ""),)
        self.assertEqual(empty_needle_rows([planted]), ["planted-empty"])
        self.assertEqual(empty_needle_rows([(("planted-named", "a", "b", "rule"),)]), [])
        tables = [self.C13_MUTANTS, self.C14_MUTANTS, self.R14_MUTANTS, self.R14_DASH_ROWS,
                  self.R14_CODE_ROWS, self.R13_REGRESSION_ROWS, self.R15_C1_ROWS,
                  self.R15_SEC_ROWS, self.R16_CODE_ROWS, self.R16_REGRESSION_ROWS,
                  self.R17_MODULE_ROWS,
                  [(fid, None, None, needle) for fid, needle in WF_FORM_RED.items()],
                  [(fid, None, None, reason) for fid, reason in WF_FORM_GREEN.items()],
                  [(fid, None, None, specs) for fid, specs in WF_FORM_TESTS.items()]]
        self.assertEqual(empty_needle_rows(tables), [])

    def test_sec_r11_the_pinned_construction_and_enumerated_arguments_are_named(self):
        """sec r11 S1/S2/S5: the one environment construction and the enumerated call arguments
        are constants of the module, and the unmutated bodies report nothing."""
        self.assertEqual(MATERIALISE_ENV_CONSTRUCTION,
                         "dict(os.environ, GIT_NO_REPLACE_OBJECTS='1')")
        for callee in ("rev_parse", "have_commit", "fetch_blob", "gate_absent", "materialise",
                       "derive_base", "print", "report", "BaseUnavailable", "handle.write"):
            with self.subTest(callee=callee):
                self.assertIn(callee, MATERIALISE_CALL_ARGS)
                self.assertEqual(list(MATERIALISE_CALL_ARGS[callee]),
                                 sorted(MATERIALISE_CALL_ARGS[callee]))
        for job, name in self.JOBS:
            with self.subTest(job=job):
                self.assertEqual(materialise_allow_list_problems(
                    name, step_named(job, name)["run"]), [])

    @unittest.skipUnless(sys.version_info >= (3, 12), "type parameters need Python 3.12")
    def test_sec_r11_s3_type_parameters_are_collected_as_bindings(self):
        tree = ast.parse("def f[T](): pass\nclass C[U, *V]: pass\ntype A = int\n")
        names = {name for name, _kind, _node in _bound_names(tree)}
        self.assertTrue({"T", "U", "V", "A"} <= names, names)

    @unittest.skipUnless(hasattr(ast, "Match"), "match statements need Python 3.10")
    def test_code_r10_c2_match_captures_are_collected_as_bindings(self):
        tree = ast.parse("match 1:\n    case [a, *rest]:\n        pass\n"
                         "    case {**more}:\n        pass\n    case x as y:\n        pass\n")
        names = {name for name, _kind, _node in _bound_names(tree)}
        self.assertEqual(names, {"a", "rest", "more", "x", "y"})

    def test_code_r10_c3_the_comment_states_the_rule_for_args_and_the_value_names(self):
        text = " ".join(Path(__file__).read_text().replace("#", " ").split())
        start = text.index("sec F1 / code C1-C3 (round 12)")
        block = text[start:text.index("MATERIALISE_MODULE_ROOTS =", start)]
        for phrase in ("code r10 C1-C4 (round 13)", "unrebound parameter",
                       "exactly one binding", "read-only environment uses",
                       "sec r10 S1-S4 (round 13)", "call position", "first terminator line",
                       "does not check", "sec r11 S1-S5 (round 14)",
                       "pinned environment construction", "unmodified",
                       "Enumerated call arguments", "decorator and no class keyword"):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, block)

    def test_code_c1_no_docstring_of_this_module_uses_the_post_derivation_wording(self):
        """code r8 C1: extends the step-order text test to every docstring of the module."""
        tree = ast.parse(Path(__file__).read_text())
        for node in ast.walk(tree):
            if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef)):
                doc = ast.get_docstring(node) or ""
                with self.subTest(node=getattr(node, "name", "module")):
                    self.assertNotIn(self.BANNED_PHRASE, " ".join(doc.split()))

    def test_no_step_runs_before_the_fold_on_a_live_event_except_the_decision(self):
        """Every step that runs on pull_request or merge_group ahead of the first fold."""
        for event in LIVE_EVENTS:
            for ran, outputs in gate_steps_that_run(event):
                names = [s["name"] for s in ran]
                first_fold = min(i for i, n in enumerate(names)
                                 if (n or "").startswith(("Fold job results", "Fail the gate")))
                for step in ran[:first_fold]:
                    with self.subTest(event=event, outputs=outputs, step=step["name"]):
                        allowed = [entry[0] for entry in GATE_ALLOW]
                        self.assertIn(step["name"], allowed)

    def test_the_resolver_is_wired_into_no_step_of_either_job(self):
        for job in (SELECT_JOB, GATE_JOB):
            for step in workflow_text.read_steps(CI_YML, job):
                with self.subTest(job=job, step=step["name"]):
                    self.assertNotEqual(step["name"], LIVE_BASE_STEP)
                    self.assertNotEqual(step["id"], "live")
                    self.assertIsNone(RESOLVER_RE.search(step["run"] or ""))
                    self.assertNotIn("steps.live", " ".join(step["env"].values()))
                    self.assertNotIn("steps.live", step["if"] or "")

    def test_a_scripts_ci_path_runs_only_in_the_named_exception_steps(self):
        select_steps = workflow_text.read_steps(CI_YML, SELECT_JOB)
        for step in select_steps:
            with self.subTest(job=SELECT_JOB, step=step["name"]):
                if step["name"] == MATERIALISE_STEP:
                    continue
                self.assertNotIn("scripts/ci/", step["run"] or "")
        for step in workflow_text.read_steps(CI_YML, GATE_JOB):
            with self.subTest(job=GATE_JOB, step=step["name"]):
                if step["name"] == GATE_MATERIALISE_STEP:
                    continue
                if "scripts/ci/" in (step["run"] or ""):
                    self.assertIn(step["name"], self.NAMED_EXCEPTIONS)

    def test_the_named_exception_folds_cannot_run_before_the_derivation(self):
        names = [s["name"] for s in workflow_text.read_steps(CI_YML, GATE_JOB)]
        self.assertLess(names.index(GATE_MATERIALISE_STEP), names.index(BOOTSTRAP_STEP))
        self.assertLess(names.index(GATE_MATERIALISE_STEP), names.index(BRANCH_TIP_STEP))

    def test_the_materialise_steps_execute_only_git(self):
        for job, name in self.JOBS:
            source = snippet_of(step_named(job, name))
            with self.subTest(job=job):
                self.assertEqual(source.count("subprocess.run("), 1)
                self.assertIn('["git", "--no-replace-objects"]', source)
                self.assertNotIn("os.system", source)
                self.assertNotIn("shell=True", source)
                self.assertNotIn("import_module", source)

    def test_the_derivation_reads_the_github_sha_context_never_head(self):
        for job, name in self.JOBS:
            step = step_named(job, name)
            source = snippet_of(step)
            with self.subTest(job=job):
                self.assertEqual(step["env"]["CONTEXT_SHA"], CONTEXT_SHA_EXPR)
                self.assertNotIn("HEAD^1", source)
                self.assertNotIn("HEAD^2", source)
                self.assertIn('env.get("CONTEXT_SHA"', source)
                self.assertNotIn("HEAD", step["env"]["CONTEXT_SHA"])

    def test_no_run_line_of_either_job_interpolates_an_expression(self):
        for job in (SELECT_JOB, GATE_JOB):
            for step in workflow_text.read_steps(CI_YML, job):
                with self.subTest(job=job, step=step["name"]):
                    self.assertNotIn("${{", step["run"] or "")

    LIBRARY_NOTE = ("base_sha.py is a library kept for the unit tests that pin its behaviour;"
                    " no workflow step runs it.")
    SELECT_ORDER_NOTE = ("Only the pinned checkout action and the echo-only Selection mode"
                         " step run before this step;")
    GATE_ORDER_NOTE = "Only the pinned checkout action runs before this step;"

    def test_no_run_line_of_any_workflow_invokes_base_sha_py(self):
        """F5: the resolver is a library; a `run:` line (or any non-comment line) naming it is red."""
        for name in PR_WORKFLOWS:
            for number, line in enumerate((WORKFLOW_DIR / name).read_text().split("\n"), 1):
                with self.subTest(workflow=name, line=number):
                    if not line.lstrip().startswith("#"):
                        self.assertNotIn("base_sha.py", line)

    def test_the_comments_and_the_docstring_state_the_step_order_as_it_is(self):
        text = CI_YML.read_text()
        self.assertEqual(text.count(self.LIBRARY_NOTE), 2)
        self.assertEqual(text.count(self.SELECT_ORDER_NOTE), 1)
        self.assertEqual(text.count(self.GATE_ORDER_NOTE), 1)
        doc = (fx.IMPACT_DIR / "base_sha.py").read_text().split('"""')[1]
        self.assertNotIn("run this one script", doc)
        self.assertIn("library", doc)
        self.assertIn("no workflow step runs it", " ".join(doc.split()))

    def test_the_stale_chain_push_wording_is_gone_from_the_workflow(self):
        text = CI_YML.read_text()
        self.assertEqual(text.count("every chain push"), 0)
        self.assertEqual(text.count("nightly full run can"), 0)
        self.assertIn("red on every release/** push and workflow_dispatch full run", text)


# sec r11 S2 rows built from the dash forms (a class body cannot build them in a comprehension).
TrustDecisionFirst.R14_DASH_ROWS = tuple(
    [("s2-%s-at-git" % tag, TrustDecisionFirst.R14_SHOWBLOB,
      '    blob = git("show", %s)\n' % form, "argument is not")
     for tag, form in TrustDecisionFirst.R14_DASH_FORMS]
    + [("s2-%s-at-rev-parse" % tag, TrustDecisionFirst.R14_DERIVED,
        TrustDecisionFirst.R14_DERIVED + "        rev_parse(%s)\n" % form, "argument is not")
       for tag, form in TrustDecisionFirst.R14_DASH_FORMS])

# code r11 C1 (round 14) and code r12 C2 (round 15): the reviewer's probe forms, one row each, built
# as (label, old, new, needle). Every row carries the needle of the rule that refuses it, found by
# running the form at 21519d95b (round 13) and at the round-14 head: 35 forms are already refused
# by a round-13 rule and sit in the round-13 regression table R13_REGRESSION_ROWS; the 12 forms the
# round-14 rules newly refuse sit in R14_CODE_ROWS. No row keeps an empty needle (an empty needle
# matches any problem line and guards no rule). A string form is inserted after the module anchor,
# ("sub", old, new) replaces once, ("sub2", (old, new), ...) replaces each pair once.
_R11_ANCHOR = "GIT_TIMEOUT_S = 120\n"
_R11_ENVLINE = 'env = dict(os.environ, GIT_NO_REPLACE_OBJECTS="1")'
_R11_ENVKW = "env=env)"
_R11_ARGV = '["git", "--no-replace-objects"] + list(args)'
_R11_GITDEF = "def git(*args):"
_R11_HAVEDEF = "def have_commit(base):"
_R11_FORMS = (
    ("c2-ns-rebind-subprocess", "subprocess = types.SimpleNamespace(run=os.system)"),
    ("c2-tuple-unpack-value", "base, path = 'X', 'Y'"),
    ("c2-for-target", "for base in 'X':\n    pass"),
    ("c2-with-as", "with open('X') as base:\n    pass"),
    ("c2-except-as", "try:\n    pass\nexcept OSError as base:\n    pass"),
    ("c2-comprehension-var", "_l = [base for base in 'X']"),
    ("c2-nested-def-param", "def _f():\n    def _g(base):\n        return base\n    return _g"),
    ("c2-global", "def _f():\n    global base\n    base = 'X'"),
    ("c2-nonlocal", "def _f():\n    base = 'X'\n    def _g():\n        nonlocal base\n"
     "        base = 'Y'\n    return _g"),
    ("c2f-assign-in-fn", ("sub", _R11_HAVEDEF, _R11_HAVEDEF + "\n    base = 'X'")),
    ("c2f-tuple-unpack-in-fn", ("sub", _R11_HAVEDEF, _R11_HAVEDEF + "\n    base, _ = 'X', 0")),
    ("c2f-for-target-in-fn", ("sub", _R11_HAVEDEF,
                              _R11_HAVEDEF + "\n    for base in ['X']:\n        pass")),
    ("c2f-except-as-in-fn", ("sub", _R11_HAVEDEF, _R11_HAVEDEF
                             + "\n    try:\n        pass\n    except OSError as base:\n        pass")),
    ("c2f-with-as-in-fn", ("sub", _R11_HAVEDEF,
                           _R11_HAVEDEF + "\n    with open('X') as base:\n        pass")),
    ("c2f-walrus-in-fn", ("sub", _R11_HAVEDEF, _R11_HAVEDEF + "\n    (base := 'X')")),
    ("c2-default-arg", "def _f(base=subprocess):\n    pass"),
    ("c2-star-import", "from os import *"),
    ("c3-alias-store", "env = os.environ\nenv['X'] = 'X'"),
    ("c3-copy-update-passed", ("sub", _R11_ENVLINE, _R11_ENVLINE + '\n    env.update(X="X")')),
    ("c3-dict-copy-update", "e = dict(os.environ)\ne.update(X='X')"),
    ("c3-environ-copy-store", "e = os.environ.copy()\ne['X'] = 'X'"),
    ("c3-def-env-default", "def _f(env=os.environ):\n    pass"),
    ("c3-setitem-alias", "m = os.environ.__setitem__"),
    ("c3-operator-setitem", "operator.setitem(os.environ, 'X', 'X')"),
    ("c3-class-setitem", "os.environ.__class__.__setitem__(os.environ, 'X', 'X')"),
    ("c3-vars-os", "vars(os)['environ']"),
    ("c3-getattr-os", "getattr(os, 'environ')"),
    ("c4-match-in-def", "def _f():\n    match 1:\n        case 1:\n            pass"),
    ("c4-match-in-class", "class _C:\n    match 1:\n        case _:\n            pass"),
    ("c5-call-arg-module", "git(subprocess)"),
    ("c5-print-os", "print(os)"),
    ("c5-star-list", "print(*[subprocess])"),
    ("c5-starstar-dict", "print(**{'m': os})"),
    ("c5-keyword-module", "print(mod=subprocess)"),
    ("c5-list-subscript-call", "[subprocess][0].run('X')"),
    ("c5-tuple-subscript", "(subprocess,)[0]"),
    ("ga-env-extra-keyword", ("sub", _R11_ENVLINE, _R11_ENVLINE[:-1] + ', X="Y")')),
    ("ga-env-literal-dict", ("sub", _R11_ENVLINE, 'env = {"GIT_NO_REPLACE_OBJECTS": "1"}')),
    ("ga-env-dict-without-environ",
     ("sub", _R11_ENVLINE, 'env = dict(GIT_NO_REPLACE_OBJECTS="1")')),
    ("ga-env-dict-starstar", ("sub", _R11_ENVLINE, 'env = dict(os.environ, **{"X": "Y"})')),
    ("ga-env-starstar-guard-kept",
     ("sub", _R11_ENVLINE, _R11_ENVLINE[:-1] + ', **{"X": "Y"})')),
    ("ga-env-literal-guard-path",
     ("sub", _R11_ENVLINE, 'env = {"GIT_NO_REPLACE_OBJECTS": "1", "PATH": os.environ["PATH"], '
      '"X": "Y"}')),
    ("ga-env-keyword-inline-dict", ("sub", _R11_ENVKW, 'env=dict(os.environ, X="Y"))')),
    ("ga-env-keyword-none", ("sub", _R11_ENVKW, "env=None)")),
    ("gb-second-run-other-fn",
     'def _f(*more):\n    return subprocess.run(["git", "--no-replace-objects"] + list(more), '
     'capture_output=True, timeout=GIT_TIMEOUT_S, env=dict(os.environ))'),
    ("gb-git-extra-param", ("sub2", (_R11_GITDEF, "def git(*args, extra=()):"),
                            (_R11_ARGV, _R11_ARGV + " + list(extra)"))),
    ("gb-caller-dash-literal", "have_commit('--X')"),
)


_R13_BASE = "git value name base: base is not an unrebound parameter"
_R14_STORES = "outside the pinned module stores"
_R14_ENV = ("environment construction is not exactly one env = dict(os.environ, "
            "GIT_NO_REPLACE_OBJECTS='1') in git()")
_R14_ENVKW = "environment keyword is not the pinned name env on subprocess.run"
# label -> (round whose rule refuses the form, needle). Round 13 = refused at 21519d95b.
_R11_RULES = {
    "c2-ns-rebind-subprocess": (13, "binds subprocess"),
    "c2-tuple-unpack-value": (14, _R14_STORES),
    "c2-for-target": (14, _R14_STORES),
    "c2-with-as": (13, "open call outside the enumerated arguments"),
    "c2-except-as": (14, _R14_STORES),
    "c2-comprehension-var": (14, _R14_STORES),
    "c2-nested-def-param": (13, "defines _g outside the pinned set"),
    "c2-global": (13, "defines _f outside the pinned set"),
    "c2-nonlocal": (13, "defines _g outside the pinned set"),
    "c2f-assign-in-fn": (13, _R13_BASE),
    "c2f-tuple-unpack-in-fn": (13, _R13_BASE),
    "c2f-for-target-in-fn": (13, _R13_BASE),
    "c2f-except-as-in-fn": (13, _R13_BASE),
    "c2f-with-as-in-fn": (13, _R13_BASE),
    "c2f-walrus-in-fn": (13, _R13_BASE),
    "c2-default-arg": (13, "defines _f outside the pinned set"),
    "c2-star-import": (13, "import statement outside the pinned set (from os import *)"),
    "c3-alias-store": (13, "stores into or deletes from env"),
    "c3-copy-update-passed": (13, "calls env.update outside the allow-list"),
    "c3-dict-copy-update": (13, "calls e.update outside the allow-list"),
    "c3-environ-copy-store": (13, "calls os.environ.copy outside the allow-list"),
    "c3-def-env-default": (13, "environment mapping os.environ used outside the read-only forms"),
    "c3-setitem-alias": (13, "reaches os.environ.__setitem__ outside the allow-list"),
    "c3-operator-setitem": (13, "calls operator.setitem outside the allow-list"),
    "c3-class-setitem": (13, "calls os.environ.__class__.__setitem__ outside the allow-list"),
    "c3-vars-os": (13, "calls vars outside the allow-list"),
    "c3-getattr-os": (13, "calls getattr outside the allow-list"),
    "c4-match-in-def": (13, "match statement outside the allow-list"),
    "c4-match-in-class": (13, "match statement outside the allow-list"),
    "c5-call-arg-module": (13, "bare reference to module subprocess"),
    "c5-print-os": (13, "bare reference to module os"),
    "c5-star-list": (13, "bare reference to module subprocess"),
    "c5-starstar-dict": (13, "bare reference to module os"),
    "c5-keyword-module": (13, "bare reference to module subprocess"),
    "c5-list-subscript-call": (13, "call on an unenumerated receiver"),
    "c5-tuple-subscript": (13, "bare reference to module subprocess"),
    "ga-env-extra-keyword": (14, _R14_ENV),
    "ga-env-literal-dict": (14, _R14_ENV),
    "ga-env-dict-without-environ": (14, _R14_ENV),
    "ga-env-dict-starstar": (14, _R14_ENV),
    "ga-env-starstar-guard-kept": (14, _R14_ENV),
    "ga-env-literal-guard-path": (14, _R14_ENV),
    "ga-env-keyword-inline-dict": (14, _R14_ENVKW),
    "ga-env-keyword-none": (14, _R14_ENVKW),
    "gb-second-run-other-fn": (13, "2 subprocess.run calls, expected exactly 1"),
    "gb-git-extra-param": (13, "subprocess.run argv is not the exact git head plus list(args)"),
    "gb-caller-dash-literal": (13, "dash argument outside the allow-list"),
}


def _r11_row(label, form):
    needle = _R11_RULES[label][1]
    if isinstance(form, str):
        return (label, _R11_ANCHOR, _R11_ANCHOR + form + "\n", needle)
    if form[0] == "sub":
        return (label, form[1], form[2], needle)
    return (label, tuple(p[0] for p in form[1:]), tuple(p[1] for p in form[1:]), needle)


assert set(_R11_RULES) == {label for label, _form in _R11_FORMS}
TrustDecisionFirst.R13_REGRESSION_ROWS = tuple(
    _r11_row(label, form) for label, form in _R11_FORMS if _R11_RULES[label][0] == 13)
TrustDecisionFirst.R14_CODE_ROWS = tuple(
    _r11_row(label, form) for label, form in _R11_FORMS if _R11_RULES[label][0] == 14)


# code r12 C1 (round 15): the four pinned module-level names each have exactly ONE binding, a direct
# module-body assignment of the pinned value. Rows are (label, old, new, needle); the needle is the
# rule that refuses the form.
_R15_C1_NEEDLE = "has no single module-level binding to its constant"
_R15_TIMEOUT = "GIT_TIMEOUT_S = 120\n"
_R15_MODES = 'REGULAR_MODES = ("100644", "100755")\n'
TrustDecisionFirst.R15_C1_ROWS = (
    ("c1-second-assign-timeout", _R15_TIMEOUT, _R15_TIMEOUT + "GIT_TIMEOUT_S = None\n",
     _R15_C1_NEEDLE),
    ("c1-second-assign-regular-modes", _R15_MODES,
     _R15_MODES + 'REGULAR_MODES = ("100644", "100755", "120000")\n', _R15_C1_NEEDLE),
    ("c1-value-change-timeout", _R15_TIMEOUT, "GIT_TIMEOUT_S = None\n", _R15_C1_NEEDLE),
    ("c1-value-change-regular-modes", _R15_MODES,
     'REGULAR_MODES = ("100644", "100755", "120000")\n', _R15_C1_NEEDLE),
    ("c1-multi-target-allowed", _R15_TIMEOUT, _R15_TIMEOUT + "GIT_TIMEOUT_S = REGULAR_MODES = None\n",
     _R15_C1_NEEDLE),
    ("c1-if-branch-allowed", _R15_TIMEOUT, _R15_TIMEOUT + "if True:\n    GIT_TIMEOUT_S = None\n",
     _R15_C1_NEEDLE),
    ("c1-try-allowed", _R15_TIMEOUT,
     _R15_TIMEOUT + "try:\n    GIT_TIMEOUT_S = None\nexcept OSError:\n    pass\n", _R15_C1_NEEDLE),
    ("c1-while-allowed", _R15_TIMEOUT, _R15_TIMEOUT + "while False:\n    GIT_TIMEOUT_S = None\n",
     _R15_C1_NEEDLE),
    ("c1-only-binding-wrapped-in-if", _R15_TIMEOUT, "if True:\n    GIT_TIMEOUT_S = 120\n",
     _R15_C1_NEEDLE),
)


# sec r12 R1/R2 (round 15): the four writes of report() decide the ok, bootstrap and reason step
# outputs and the summary line, so their arguments are enumerated and the names in them (ok,
# reason, bootstrap, line) resolve by binding. Rows are (label, old, new, needle).
_R15_DEF = "def report(ok, reason, bootstrap=False):\n"
_R15_W_OK = '        handle.write("ok=%s\\n" % ("true" if ok else "false"))\n'
_R15_W_BOOT = '        handle.write("bootstrap=%s\\n" % ("true" if bootstrap else "false"))\n'
_R15_W_REASON = '        handle.write("reason=%s\\n" % reason)\n'
_R15_LINE = '    line = "impact: base files unavailable (%s)" % reason\n'
_R15_AUG = '        line += "; bootstrap: the base sha has no scripts/ci/impact/gate.py"\n'
_R15_PRINT = "    print(line)\n"
_R15_RUNNER = 'os.environ.get("GITHUB_ACTIONS")'
_R15_WRITE = "step output write outside the enumerated arguments"
_R15_PARAM = "is not an unrebound parameter without a default"
_R15_DEFAULT = "is not an unrebound parameter with its pinned default"
_R15_LINE_RULE = "is not bound only to its pinned assignment and one pinned augmented literal"
# Regression pins of this table (green at 02c1ac64a, refused there with their needle): the
# print-argument row r2-print-other-name and r1-report-call-forged-bootstrap (code r13 F5, sec r13
# S3); the other 16 rows are red-first. R15_REGRESSION_PINS names them and a test asserts it.
TrustDecisionFirst.R15_SEC_ROWS = (
    ("r1-write-bootstrap-runner-conditioned", _R15_W_BOOT,
     '        handle.write("bootstrap=%s\\n" % ("true" if bootstrap or ' + _R15_RUNNER
     + ' else "false"))\n', _R15_WRITE),
    ("r1-write-ok-literal", _R15_W_OK, '        handle.write("ok=%s\\n" % "true")\n', _R15_WRITE),
    ("r1-write-reason-from-environment", _R15_W_REASON,
     '        handle.write("reason=%s\\n" % os.environ.get("X", ""))\n', _R15_WRITE),
    ("r1-fifth-write-bootstrap-true", _R15_W_REASON,
     _R15_W_REASON + '        handle.write("bootstrap=true\\n")\n', _R15_WRITE),
    ("r1-bootstrap-rebound-on-runner", _R15_DEF,
     _R15_DEF + "    bootstrap = bootstrap or bool(" + _R15_RUNNER + ")\n", _R15_DEFAULT),
    ("r1-bootstrap-default-true", _R15_DEF, "def report(ok, reason, bootstrap=True):\n",
     _R15_DEFAULT),
    ("r1-ok-rebound-on-runner", _R15_DEF,
     _R15_DEF + "    ok = ok and not " + _R15_RUNNER + "\n", _R15_PARAM),
    ("r1-reason-rebound-from-environment", _R15_DEF,
     _R15_DEF + '    reason = os.environ.get("X", reason)\n', _R15_PARAM),
    ("r2-line-rebound-from-environment", _R15_LINE,
     _R15_LINE + '    line = os.environ.get("X", "")\n', _R15_LINE_RULE),
    ("r2-line-extended-from-environment", _R15_PRINT,
     '    line += os.environ.get("X", "")\n' + _R15_PRINT, _R15_LINE_RULE),
    ("r2-line-rebound-on-runner", _R15_PRINT,
     "    if " + _R15_RUNNER + ':\n        line = os.environ["X"]\n' + _R15_PRINT, _R15_LINE_RULE),
    ("r2-line-assignment-value-changed", _R15_LINE,
     '    line = "impact: base files unavailable (%s)" % os.environ.get("X", reason)\n',
     _R15_LINE_RULE),
    ("r2-line-literal-changed", _R15_AUG,
     '        line += "; bootstrap: " + os.environ.get("X", "")\n', _R15_LINE_RULE),
    ("r2-print-other-name", _R15_PRINT, "    print(summary)\n", "print call outside the enumerated"),
    ("r1-write-bootstrap-literal-true", _R15_W_BOOT,
     '        handle.write("bootstrap=%s\\n" % "true")\n', _R15_WRITE),
    ("r1-summary-write-from-environment", '            handle.write(line + "\\n")\n',
     '            handle.write(os.environ.get("HOME", "") + "\\n")\n', _R15_WRITE),
    ("r2-line-assignment-runner-conditioned", _R15_LINE,
     '    line = "impact: base files unavailable (%s)" % (' + _R15_RUNNER
     + ' and os.environ.get("HOME", "") or reason)\n', _R15_LINE_RULE),
    ("r1-report-call-forged-bootstrap", "report(False, str(exc), gate_absent(derived))",
     "report(False, str(exc), True)", "call argument is not enumerated for report"),
)


# code r13 F1/F3 and sec r13 S1 (round 16): the control flow of every local function of the
# Materialise heredoc decides the trust values (bootstrap, the derived base), so the second layer
# pins the normalised ast.dump of each of them, independent of MATERIALISE_SHA256; the one
# augmented literal of `line` is the sole body of `if bootstrap:` directly after its assignment.
# Rows are (label, old, new, needle). R16_CODE_ROWS are all red at d883f264c (they carry a needle
# no earlier rule emits); R16_REGRESSION_ROWS are green at d883f264c because an earlier rule
# already refuses them with that needle, and they stay as declared regression pins.
_R16_RUNNER = 'os.environ.get("GITHUB_ACTIONS")'
_R16_GA_DEF = "def gate_absent(base):\n"
_R16_GA_RET = "    return tree.returncode == 0 and not tree.stdout.strip()\n"
_R16_GA_EXC = "    except BaseUnavailable:\n        return False\n" + _R16_GA_RET
_R16_PARENT = '        parent = rev_parse(context + "^1^{commit}")\n'
_R16_RET_PARENT = "        return parent\n"
_R16_RET_RAW = "        return raw\n"
_R16_IFB = "    if bootstrap:\n"
_R16_AUG4 = '    line += "; bootstrap: the base sha has no scripts/ci/impact/gate.py"\n'
_R16_PIN = "differs from its pinned normalised ast.dump"
_R16_GATE_ABSENT = "function gate_absent " + _R16_PIN
_R16_MAIN = "function main " + _R16_PIN
_R16_DERIVE = "function derive_base " + _R16_PIN
_R16_AUG_SHAPE = "sole body of `if bootstrap:` directly after"
_R16_SUMMARY_SHAPE = "summary write is not the sole body"
TrustDecisionFirst.R16_CODE_ROWS = (
    ("f1-gate-absent-environ-return-true", _R16_GA_DEF,
     _R16_GA_DEF + "    if " + _R16_RUNNER + ":\n        return True\n", _R16_GATE_ABSENT),
    ("f1-gate-absent-return-true", _R16_GA_DEF, _R16_GA_DEF + "    return True\n",
     _R16_GATE_ABSENT),
    ("f1-gate-absent-except-true", _R16_GA_EXC,
     _R16_GA_EXC.replace("return False", "return True", 1), _R16_GATE_ABSENT),
    ("f1-gate-absent-return-bool-environ", _R16_GA_RET,
     "    return bool(" + _R16_RUNNER + ")\n", _R16_GATE_ABSENT),
    ("f1-gate-absent-try-else-true", _R16_GA_EXC,
     "    except BaseUnavailable:\n        return False\n    else:\n        return True\n"
     + _R16_GA_RET, _R16_GATE_ABSENT),
    ("f1-main-report-under-condition", '        report(False, "environment-unusable")\n',
     "        if " + _R16_RUNNER + ":\n            report(False, str(exc), gate_absent(derived))\n"
     + '        report(False, "environment-unusable")\n', _R16_MAIN),
    ("f1-main-early-ok-on-runner", 'def main():\n    derived = ""\n',
     'def main():\n    derived = ""\n    if ' + _R16_RUNNER + ':\n        report(True, "")\n'
     "        return 0\n", _R16_MAIN),
    ("s1-gate-absent-runner", _R16_GA_RET,
     "    return bool(" + _R16_RUNNER + ") or (tree.returncode == 0 and not tree.stdout.strip())\n",
     _R16_GATE_ABSENT),
    ("s1-parent-is-head-runner", _R16_PARENT,
     _R16_PARENT + "        if " + _R16_RUNNER
     + ':\n            parent = rev_parse(context + "^2^{commit}")\n', _R16_DERIVE),
    ("s1-return-context-runner", _R16_RET_PARENT,
     "        if " + _R16_RUNNER + ":\n            return context\n" + _R16_RET_PARENT,
     _R16_DERIVE),
    ("s1-merge-group-return-head-runner", _R16_RET_RAW,
     "        if " + _R16_RUNNER + ':\n            return env.get("HEAD_SHA", "")\n'
     + _R16_RET_RAW, _R16_DERIVE),
    ("f3-augment-in-loop", _R16_IFB + _R15_AUG,
     "    while bootstrap:\n" + _R15_AUG + "        break\n", _R16_AUG_SHAPE),
    ("f3-augment-unconditional", _R16_IFB + _R15_AUG, _R16_AUG4, _R16_AUG_SHAPE),
    ("f3-augment-under-environ-if", _R16_IFB, "    if " + _R16_RUNNER + ":\n", _R16_AUG_SHAPE),
    ("f3-augment-under-not-bootstrap", _R16_IFB, "    if not bootstrap:\n", _R16_AUG_SHAPE),
    ("f3-summary-write-under-ok", "    if summary:\n", "    if ok:\n", _R16_SUMMARY_SHAPE),
    ("f3-summary-write-in-loop", "    if summary:\n", "    while summary:\n", _R16_SUMMARY_SHAPE),
)
TrustDecisionFirst.R16_REGRESSION_ROWS = (
    ("f1-gate-absent-redefined-later", "def report(ok, reason, bootstrap=False):\n",
     "def gate_absent(base):\n    return True\n\n\ndef report(ok, reason, bootstrap=False):\n",
     "gate_absent defined more than once"),
    ("f1-gate-absent-lambda-rebinding", "def main():\n",
     "gate_absent = lambda base: True\n\n\ndef main():\n", "lambda statement outside the allow-list"),
)


# sec r14 S1 (round 17): the module body outside the pinned functions is one ordered statement
# sequence. Rows are (label, old, new, needle) and every row carries the needle "module body"; the
# 8 reviewer forms come first, then the 7 placement forms of the prompt. All 15 are red at 47f4d9173
# (no earlier rule emits the needle).
_R17_GUARD = 'if __name__ == "__main__":\n    sys.exit(main())\n'
_R17_NEEDLE = "module body"
_R17_RUNNER = 'os.environ.get("GITHUB_ACTIONS")'


def _r17_before_guard(label, statement):
    return (label, _R17_GUARD, statement + "\n\n\n" + _R17_GUARD, _R17_NEEDLE)


TrustDecisionFirst.R17_MODULE_ROWS = (
    ("m-guard-early-main-runner", _R17_GUARD,
     "if " + _R17_RUNNER + ":\n    sys.exit(main())\n\n\n" + _R17_GUARD, _R17_NEEDLE),
    _r17_before_guard("m-early-report-ok-runner",
                      "if " + _R17_RUNNER + ':\n    report(True, "")\n    sys.exit(0)'),
    _r17_before_guard("m-early-report-ok", 'report(True, "")\nsys.exit(0)'),
    _r17_before_guard("m-early-exit-runner", "if " + _R17_RUNNER + ":\n    sys.exit(0)"),
    _r17_before_guard("m-early-report-unusable-runner",
                      "if " + _R17_RUNNER + ':\n    report(False, "environment-unusable")\n'
                      "    sys.exit(0)"),
    _r17_before_guard("m-module-try-exit", "try:\n    pass\nexcept Exception:\n    sys.exit(0)"),
    _r17_before_guard("m-early-main-twice", "main()"),
    _r17_before_guard("m-main-then-report-ok-runner",
                      "if " + _R17_RUNNER + ':\n    main()\n    report(True, "")\n    sys.exit(0)'),
    ("m-statement-between-defs", "def have_commit(base):\n",
     "pass\n\n\ndef have_commit(base):\n", _R17_NEEDLE),
    ("m-statement-after-guard", _R17_GUARD, _R17_GUARD + "pass\n", _R17_NEEDLE),
    ("m-guard-duplicated", _R17_GUARD, _R17_GUARD + "\n\n" + _R17_GUARD, _R17_NEEDLE),
    ("m-second-main-guard-other-body", _R17_GUARD,
     'if __name__ == "__main__":\n    report(True, "")\n\n\n' + _R17_GUARD, _R17_NEEDLE),
    ("m-import-moved-after-def", ("import shutil\n", "def have_commit(base):\n"),
     ("", "import shutil\n\n\ndef have_commit(base):\n"), _R17_NEEDLE),
    _r17_before_guard("m-module-exec", 'exec("pass")'),
    ("m-module-try-around-main", _R17_GUARD,
     'if __name__ == "__main__":\n    try:\n        sys.exit(main())\n    except Exception:\n'
     "        sys.exit(0)\n", _R17_NEEDLE),
)


# code r13 F5 / sec r13 S3: the rows of R15_SEC_ROWS that 02c1ac64a already refused with their
# needle (regression pins, not red-first rows).
TrustDecisionFirst.R15_REGRESSION_PINS = ("r2-print-other-name", "r1-report-call-forged-bootstrap")


def empty_needle_rows(tables):
    """Labels of the rows whose needle (the fourth item) is empty: an empty needle matches any
    problem line and so guards no rule."""
    return [row[0] for table in tables for row in table if not row[3]]


class StrictWorkflowLoader(unittest.TestCase):
    """r7 F1: the loader reads what the runner reads, or refuses; it never skips a key."""

    def test_quoted_keys_spaced_colons_flow_mappings_and_block_scalars_are_read(self):
        doc = yaml_subset_load(
            "a:\n  \"b\" : 1\n  'c': {d: e, 'f' : g}\n  h: |\n    x\n    y\n"
            "k: [m, n]\nq:\n  - r: s\n    t : u\n  - {v: w}\n  - plain\n")
        self.assertEqual(doc, {"a": {"b": "1", "c": {"d": "e", "f": "g"}, "h": "x\ny\n"},
                               "k": ["m", "n"],
                               "q": [{"r": "s", "t": "u"}, {"v": "w"}, "plain"]})

    def test_constructs_the_loader_cannot_read_are_refused(self):
        refused = {
            "anchor": "a: &x 1\n",
            "alias": "a: *x\n",
            "tag": "a: !!str 1\n",
            "tab indent": "a:\n\tb: 1\n",
            "multi-line plain": "a: b\n  c\n",
            "document marker": "---\na: 1\n",
            "duplicate key": "a: 1\na: 2\n",
            "duplicate quoted key": "a: 1\n\"a\": 2\n",
            "merge key": "a: 1\n<<: {b: 2}\n",
            "multi-line quote": "a: \"b\n  c\"\n",
            "open flow": "a: {b: 1\n",
            "text after flow": "a: [b] c\n",
            "plain holding colon": "a: b: c\n",
            "complex key": "? a\n: b\n",
            "unexpected indent": "a: 1\n   b: 2\n",
        }
        for label, text in refused.items():
            with self.subTest(label=label):
                with self.assertRaises(YamlSubsetError):
                    yaml_subset_load(text)

    def test_the_live_workflow_loads_with_every_step_a_mapping(self):
        doc = yaml_subset_load(CI_YML.read_text())
        for job in (SELECT_JOB, GATE_JOB):
            self.assertTrue(all(isinstance(s, dict) for s in doc["jobs"][job]["steps"]))

    def test_the_loader_agrees_with_the_line_reader_on_the_pinned_steps(self):
        doc = yaml_subset_load(CI_YML.read_text())
        for job in (SELECT_JOB, GATE_JOB):
            parsed = doc["jobs"][job]["steps"]
            lined = workflow_text.read_steps(CI_YML, job)
            self.assertEqual(len(parsed), len(lined), job)
            for left, right in zip(parsed, lined):
                with self.subTest(job=job, step=right["name"]):
                    self.assertEqual(left.get("name"), right["name"])
                    self.assertEqual(left.get("run"), right["run"])
                    self.assertEqual(left.get("env", {}), right["env"])


class TrustWindowMutants(unittest.TestCase):
    """r7 F1-F3: each mutant of the live ci.yml or of a Materialise run block is red."""

    SELECTION_ID = "      - name: Selection mode\n        id: mode\n"
    CHECKOUT_WITH = "        with:\n          fetch-depth: 0\n          persist-credentials: false\n"

    def live(self):
        return CI_YML.read_text()

    def mutate(self, old, new, text=None, count=1):
        text = self.live() if text is None else text
        self.assertEqual(text.count(old), count, old)
        return text.replace(old, new, 1)

    def assert_red(self, text):
        problems = pre_trust_problems(text)
        self.assertTrue(problems)
        return problems

    def test_the_control_is_green(self):
        self.assertEqual(pre_trust_problems(self.live()), [])

    # ---- F1: the parsed key set, whatever the YAML spelling
    def test_F1_quoted_step_shell_key_is_red(self):
        self.assert_red(self.mutate(self.SELECTION_ID, self.SELECTION_ID + '        "shell": bash\n'))
        self.assert_red(self.mutate(self.SELECTION_ID, self.SELECTION_ID + "        'shell': bash\n"))

    def test_F1_spaced_colon_step_shell_key_is_red(self):
        self.assert_red(self.mutate(self.SELECTION_ID, self.SELECTION_ID + "        shell : bash\n"))

    def test_F1_flow_mapped_step_with_a_shell_is_red(self):
        step = "      - {name: Extra, shell: bash, run: 'true'}\n"
        self.assert_red(self.mutate(self.SELECTION_ID, step + self.SELECTION_ID))

    def test_F1_flow_mapped_env_with_a_start_up_key_is_red(self):
        old = (self.SELECTION_ID + "        env:\n"
               "          ENFORCE: ${{ vars.CI_IMPACT_ENFORCE }}\n")
        problems = self.assert_red(self.mutate(
            old, self.SELECTION_ID + "        env: {ENFORCE: x, BASH_ENV: /x}\n"))
        self.assertTrue(any("BASH_ENV" in p for p in problems))

    def test_F1_block_scalar_step_shell_key_is_red(self):
        self.assert_red(self.mutate(self.SELECTION_ID,
                                    self.SELECTION_ID + "        shell: |\n          bash\n"))

    def test_F1_quoted_and_spaced_env_keys_are_red(self):
        anchor = (self.SELECTION_ID + "        env:\n"
                  "          ENFORCE: ${{ vars.CI_IMPACT_ENFORCE }}\n")
        for extra in ('          "BASH_ENV": /x\n', "          'BASH_ENV': /x\n",
                      "          BASH_ENV : /x\n"):
            with self.subTest(extra=extra):
                problems = self.assert_red(self.mutate(anchor, anchor + extra))
                self.assertTrue(any("BASH_ENV" in p for p in problems))

    def test_F1_quoted_submodules_with_key_is_red(self):
        text = self.mutate(self.CHECKOUT_WITH, self.CHECKOUT_WITH + '          "submodules": true\n',
                           count=self.live().count(self.CHECKOUT_WITH))
        self.assert_red(text)

    def test_F1_a_construct_the_loader_cannot_read_is_red_not_skipped(self):
        problems = self.assert_red(self.mutate(self.SELECTION_ID,
                                               self.SELECTION_ID + "        shell: &s bash\n"))
        self.assertIn("unreadable", problems[0])

    # ---- F2: the effective environment, not just the step
    def test_F2_workflow_level_bash_env_is_red(self):
        text = self.mutate('\n  CARGO_INCREMENTAL: "0"\n', '\n  CARGO_INCREMENTAL: "0"\n  BASH_ENV: /x\n')
        self.assertTrue(any("BASH_ENV" in p for p in self.assert_red(text)))

    def test_F2_job_level_bash_env_on_the_select_job_is_red(self):
        old = "    env:\n      RUSTUP_TOOLCHAIN: stable\n"
        text = self.mutate(old, old + "      BASH_ENV: /x\n")
        self.assertTrue(any("BASH_ENV" in p for p in self.assert_red(text)))

    def test_F2_job_level_bash_env_on_the_gate_job_is_red(self):
        old = "    timeout-minutes: 5\n    steps:\n"
        text = self.mutate(old, "    timeout-minutes: 5\n    env:\n      BASH_ENV: /x\n    steps:\n")
        self.assertTrue(any("BASH_ENV" in p for p in self.assert_red(text)))

    def test_F2_workflow_level_defaults_run_shell_is_red(self):
        text = self.mutate("\njobs:\n", "\ndefaults:\n  run:\n    shell: bash\n\njobs:\n")
        self.assertTrue(any("defaults.run.shell" in p for p in self.assert_red(text)))

    def test_F2_job_level_defaults_run_working_directory_is_red(self):
        old = "    timeout-minutes: 5\n    steps:\n"
        text = self.mutate(old, "    timeout-minutes: 5\n    defaults:\n      run:\n"
                                "        working-directory: .git\n    steps:\n")
        self.assertTrue(any("working-directory" in p for p in self.assert_red(text)))

    def test_F2_job_level_defaults_run_shell_on_the_select_job_is_red(self):
        old = "    env:\n      RUSTUP_TOOLCHAIN: stable\n"
        text = self.mutate(old, old.replace("    env:", "    defaults:\n      run:\n"
                                            "        shell: bash\n    env:"))
        self.assertTrue(any("defaults.run.shell" in p for p in self.assert_red(text)))

    # ---- S18 (security r7): every setting that applies to a step before the trust check
    def test_S18_workflow_level_pythonpath_is_red(self):
        text = self.mutate('\n  CARGO_INCREMENTAL: "0"\n', '\n  CARGO_INCREMENTAL: "0"\n  PYTHONPATH: /x\n')
        self.assertTrue(any("PYTHONPATH" in p for p in self.assert_red(text)))

    def test_S18_workflow_level_defaults_run_working_directory_is_red(self):
        text = self.mutate("\njobs:\n", "\ndefaults:\n  run:\n    working-directory: .git\n\njobs:\n")
        self.assertTrue(any("defaults.run.working-directory" in p for p in self.assert_red(text)))

    def test_S18_job_level_container_is_red_on_both_jobs(self):
        for old, new in (("    env:\n      RUSTUP_TOOLCHAIN: stable\n",
                          "    container: ubuntu:latest\n    env:\n      RUSTUP_TOOLCHAIN: stable\n"),
                         ("    timeout-minutes: 5\n    steps:\n",
                          "    timeout-minutes: 5\n    container: ubuntu:latest\n    steps:\n")):
            with self.subTest(old=old):
                self.assertTrue(any("container" in p for p in self.assert_red(self.mutate(old, new))))

    # ---- F3: the Materialise block is pinned by content
    def run_of(self, job, name):
        return step_named(job, name)["run"]

    def test_F3_appended_commands_that_execute_a_checkout_file_are_red(self):
        appended = ("python3 scripts/ci/base_sha.py", "source .env", ". ./a", "bash ./b", "./c")
        for job, name in TrustDecisionFirst.JOBS:
            for line in appended:
                with self.subTest(job=job, line=line):
                    problems = materialise_problems(name, self.run_of(job, name) + line + "\n")
                    self.assertTrue(any("sha256" in p for p in problems))
                    self.assertTrue(any("heredoc" in p for p in problems))

    def test_F3_a_checkout_path_inside_the_body_is_red_beyond_the_hash(self):
        for job, name in TrustDecisionFirst.JOBS:
            run = self.run_of(job, name)
            for line in ('subprocess.run(["./x"])', 'subprocess.run(["python3", "scripts/x.py"])',
                         "import runpy", "exec(open('.env').read())"):
                with self.subTest(job=job, line=line):
                    problems = materialise_problems(name, run.replace("\nPY\n", "\n" + line + "\nPY\n"))
                    rest = [p for p in problems if "sha256" not in p]
                    self.assertTrue(rest, problems)

    def test_F3_one_changed_byte_is_red_and_names_both_hashes_not_the_block(self):
        for job, name in TrustDecisionFirst.JOBS:
            run = self.run_of(job, name)
            changed = run.replace("GIT_TIMEOUT_S = 120", "GIT_TIMEOUT_S = 121")
            self.assertNotEqual(changed, run)
            problems = materialise_problems(name, changed)
            # code r12 C1: the changed value is also refused by the pinned-value rule.
            digest = [p for p in problems if "sha256" in p]
            self.assertEqual(len(digest), 1, problems)
            # sec r14 S1: the module-body pin also sees the changed constant.
            self.assertEqual(len(problems), 3, problems)
            second = [p for p in problems if "sha256" not in p]
            self.assertEqual(len(second), 2, problems)
            self.assertIn("module body", second[0])
            self.assertIn("GIT_TIMEOUT_S", second[1])
            self.assertIn(name, digest[0])
            self.assertIn(run_digest(changed), digest[0])
            self.assertIn(MATERIALISE_SHA256[name], digest[0])
            self.assertNotIn("GIT_TIMEOUT_S", digest[0])

    def test_F3_a_line_appended_in_ci_yml_after_either_heredoc_is_red(self):
        text = self.live()
        marker = "          PY\n"
        first = text.index(marker)
        second = text.index(marker, text.index("      - name: Materialise the base gate (#8240)\n"))
        for index, line in enumerate(("python3 scripts/ci/base_sha.py", "source .env", "./x",
                                      ". ./a")):
            position = (first, second)[index % 2]
            mutated = text[:position + len(marker)] + "          " + line + "\n" \
                + text[position + len(marker):]
            with self.subTest(line=line):
                self.assert_red(mutated)


class GitHardening(BaseCase):
    """S15: every git call of the materialise steps ignores replace objects."""

    def recording_path(self):
        log = self.tmp / "git-calls.jsonl"
        log.write_text("")
        wrapper_dir = self.tmp / "recbin"
        shutil.rmtree(str(wrapper_dir), ignore_errors=True)
        wrapper_dir.mkdir()
        wrapper = wrapper_dir / "git"
        real = shutil.which("git")
        wrapper.write_text(
            "#!%s\nimport json\nimport os\nimport sys\n"
            "with open(%r, 'a') as handle:\n"
            "    handle.write(json.dumps([os.environ.get('GIT_NO_REPLACE_OBJECTS'),"
            " sys.argv[1:]]) + '\\n')\n"
            "os.execv(%r, [%r] + sys.argv[1:])\n" % (sys.executable, str(log), real, real))
        wrapper.chmod(wrapper.stat().st_mode | stat.S_IXUSR)
        return log, str(wrapper_dir) + os.pathsep + os.environ["PATH"]

    def test_every_git_call_of_both_steps_sets_the_no_replace_guards(self):
        base = self.commit_selector()
        for job, name in ((SELECT_JOB, MATERIALISE_STEP), (GATE_JOB, GATE_MATERIALISE_STEP)):
            log, path = self.recording_path()
            step = step_named(job, name)
            head = fx.git(self.repo, "rev-parse", "HEAD")
            env = dict(derived_env(base, head), PATH=path,
                       IMPACT_FILES=step["env"]["IMPACT_FILES"])
            shutil.rmtree(str(self.dest), ignore_errors=True)
            _, lines, summary, _ = run_snippet(snippet_of(step), self.repo, env)
            self.assertEqual(lines.get("ok"), "true", summary)
            calls = [json.loads(item) for item in log.read_text().split("\n") if item]
            self.assertGreater(len(calls), 3)
            for flag, argv in calls:
                with self.subTest(job=job, argv=argv):
                    self.assertEqual(flag, "1")
                    self.assertEqual(argv[0], "--no-replace-objects")


LIVE_EVENTS = ("pull_request", "merge_group")
BRANCH_EVENTS = ("push", "schedule", "workflow_dispatch")
OTHER_EVENTS = BRANCH_EVENTS + ("release", "workflow_run", "")
OUTPUT_VALUES = (None, "true", "false")


def gate_steps_that_run(event):
    """Yield (steps, outputs) for every output combination of the ci-gate job.

    `steps` are the ci-gate steps whose `if:` holds for `event`. The base step
    is skipped on a branch-tip event, so its outputs are empty there; every
    output combination is still tried so a guard that only works for one
    combination is caught.
    """
    steps = workflow_text.read_steps(CI_YML, GATE_JOB)
    for ok in OUTPUT_VALUES:
        for bootstrap in OUTPUT_VALUES:
            outputs = {k: v for k, v in (("ok", ok), ("bootstrap", bootstrap)) if v}
            context = {"github": {"event_name": event},
                       "steps": {"base": {"outputs": outputs}, "live": {"outputs": {}}}}
            ran = [s for s in steps
                   if s["if"] is None or gha_expr.evaluate_job_if(s["if"], context)]
            yield ran, outputs


class BranchTipGate(unittest.TestCase):
    """R5-RISK: push, schedule and workflow_dispatch run the gate on the branch tip.

    decision: on push, schedule and workflow_dispatch the gate runs from the
    checked-out tree over failing closed because there is no second party to
    judge itself: the tree under test is already the branch tip, and a gate
    that is red on every release/** push and workflow_dispatch full run can
    never be made required
    """

    def test_a_branch_tip_event_runs_exactly_the_branch_tip_fold(self):
        for event in OTHER_EVENTS:
            for ran, outputs in gate_steps_that_run(event):
                folds = [s["name"] for s in ran if (s["name"] or "").startswith("Fold job results")]
                with self.subTest(event=event, outputs=outputs):
                    self.assertEqual(folds, [BRANCH_TIP_STEP])

    def test_a_branch_tip_event_skips_the_live_base_and_the_materialise_steps(self):
        for event in OTHER_EVENTS:
            for ran, outputs in gate_steps_that_run(event):
                names = [s["name"] for s in ran]
                with self.subTest(event=event, outputs=outputs):
                    self.assertNotIn(LIVE_BASE_STEP, names)
                    self.assertNotIn(GATE_MATERIALISE_STEP, names)

    def test_a_live_base_event_never_runs_the_branch_tip_fold(self):
        for event in LIVE_EVENTS:
            for ran, outputs in gate_steps_that_run(event):
                names = [s["name"] for s in ran]
                with self.subTest(event=event, outputs=outputs):
                    self.assertNotIn(BRANCH_TIP_STEP, names)
                    self.assertIn(GATE_MATERIALISE_STEP, names)

    def test_the_fail_step_can_only_run_on_a_live_base_event(self):
        for event in OTHER_EVENTS + LIVE_EVENTS:
            for ran, outputs in gate_steps_that_run(event):
                with self.subTest(event=event, outputs=outputs):
                    if FAIL_STEP in [s["name"] for s in ran]:
                        self.assertIn(event, LIVE_EVENTS)

    def test_exactly_one_fold_or_fail_step_runs_on_every_event(self):
        """S14: no event ends with zero verdict steps (a silent pass) or with two."""
        verdict = (BASE_GATE_STEP, BOOTSTRAP_STEP, BRANCH_TIP_STEP, FAIL_STEP)
        consistent = (("true", None), ("true", "false"), ("false", "true"),
                      ("false", "false"), ("false", None))
        for event in OTHER_EVENTS + LIVE_EVENTS:
            for ran, outputs in gate_steps_that_run(event):
                live = event in LIVE_EVENTS
                if live and (outputs.get("ok"), outputs.get("bootstrap")) not in consistent:
                    continue
                names = [s["name"] for s in ran if s["name"] in verdict]
                with self.subTest(event=event, outputs=outputs):
                    self.assertEqual(len(names), 1, names)

    def test_the_fail_step_still_runs_when_a_live_base_event_has_no_base_gate(self):
        hit = [outputs for ran, outputs in gate_steps_that_run("pull_request")
               if FAIL_STEP in [s["name"] for s in ran]]
        self.assertTrue(hit)

    def test_the_branch_tip_fold_runs_the_checked_out_gate_and_names_the_event(self):
        step = step_named(GATE_JOB, BRANCH_TIP_STEP)
        self.assertIn("python3 -I " + GATE_SCRIPT + " --needs", step["run"])
        self.assertIn("--github-ref", step["run"])
        self.assertIn("ci-gate: no live base needed (", step["run"])
        self.assertIn("the checked-out tree is the branch tip", step["run"])
        self.assertIn("github.event_name", " ".join(step["env"].values()))
        self.assertIn("!cancelled()", step["if"])

    def test_no_step_that_runs_on_a_branch_tip_event_reads_the_base_copy(self):
        for event in OTHER_EVENTS:
            for ran, outputs in gate_steps_that_run(event):
                for step in ran:
                    text = (step["run"] or "") + " ".join(step["env"].values())
                    with self.subTest(event=event, step=step["name"]):
                        self.assertNotIn(BASE_DIR, text)



PERMISSIVE_GATE = (
    "import sys\n"
    "print('PERMISSIVE-GATE-RAN')\n"
    "sys.exit(0)\n"
)


class DerivedBase(BaseCase):
    """S15 (R4-F12): both materialise steps derive the base before any PR code can run.

    decision: the trust decision runs before any checkout file executes and the
    derivation is inline with no resolver script run over keeping a resolver
    step first because any PR-tree step that runs earlier in the job can rewrite
    the git state and PATH the derivation reads (the resolver is a library for
    its unit tests; no workflow step runs it)

    The hostile cases below model the reviewer probes P2, P3, P4 and P8: a
    PR-tree step that had run first rewrites the checkout's git state (moves
    HEAD, adds a replace ref). The workflow no longer has such a step (see
    TrustDecisionFirst); the materialise step still refuses the rewritten state.
    """

    def build(self):
        """main: c0 (no gate.py) -> c1 (selector); PR p0 (permissive gate) -> p1; merge M on HEAD."""
        c0 = self.base
        git = lambda *a: fx.git(self.repo, *a)
        self.commit_selector()
        c1 = git("rev-parse", "HEAD")
        git("checkout", "-q", "-b", "pr")
        p0 = fx.commit_change(self.repo, {IMPACT_REL + "/gate.py": PERMISSIVE_GATE})
        p1 = fx.commit_change(self.repo, {"pr.txt": "pr\n"})
        git("checkout", "-q", "main")
        later = fx.commit_change(self.repo, {"later.txt": "later\n"})
        git("checkout", "-q", "-b", "merge-ref")
        git("merge", "-q", "--no-ff", "-m", "merge", "pr")
        merge = git("rev-parse", "HEAD")
        return {"c0": c0, "c1": c1, "p0": p0, "p1": p1, "base": later, "merge": merge}

    def forged_merge(self, shas):
        """A forged merge commit: first parent the permissive PR commit, second the real head."""
        tree = fx.git(self.repo, "rev-parse", shas["p1"] + "^{tree}")
        return fx.git(self.repo, "commit-tree", tree, "-p", shas["p0"], "-p", shas["p1"],
                      "-m", "forged")

    def hostile_move_head(self, commit):
        fx.git(self.repo, "checkout", "-q", "--detach", commit)

    def hostile_replace(self, real, forged):
        fx.git(self.repo, "replace", "-f", real, forged)

    def run_both(self, event, head, context_sha, merge_group_base="", extra_env=None):
        """Run both materialise steps; return {job: (lines, summary)}."""
        results = {}
        for job, name in ((SELECT_JOB, MATERIALISE_STEP), (GATE_JOB, GATE_MATERIALISE_STEP)):
            step = step_named(job, name)
            env = {"IMPACT_FILES": step["env"]["IMPACT_FILES"], "EVENT_NAME": event,
                   "HEAD_SHA": head, "MERGE_GROUP_BASE_SHA": merge_group_base,
                   "CONTEXT_SHA": context_sha}
            env.update(extra_env or {})
            shutil.rmtree(str(self.dest), ignore_errors=True)
            _, lines, summary, _ = run_snippet(snippet_of(step), self.repo, env)
            results[job] = (lines, summary)
        return results

    def assert_gate_fails_on_mismatch(self, results):
        for job, (lines, summary) in results.items():
            with self.subTest(job=job):
                self.assertEqual(lines.get("ok"), "false", summary)
                self.assertEqual(lines.get("reason"), "base-sha-mismatch", summary)
                self.assertNotEqual(lines.get("bootstrap"), "true", summary)
        gate_lines = results[GATE_JOB][0]
        self.assertEqual(GateBaseRead.plan(self, gate_lines), [FAIL_STEP])
        code, text = GateBaseRead.run_fail_step(self, gate_lines["reason"])
        self.assertNotEqual(code, 0)
        self.assertIn("base-sha-mismatch", text)
        self.assertFalse((self.dest / "impact" / "gate.py").exists())

    def test_the_honest_checkout_derives_the_merge_ref_first_parent_on_both_events(self):
        shas = self.build()
        for event, mg_base in (("pull_request", ""), ("merge_group", shas["base"])):
            results = self.run_both(event, shas["p1"], shas["merge"], mg_base)
            for job, (lines, summary) in results.items():
                with self.subTest(event=event, job=job):
                    self.assertEqual(lines.get("ok"), "true", summary)
            self.assertEqual(GateBaseRead.plan(self, results[GATE_JOB][0]), [BASE_GATE_STEP])
            copy = (self.dest / "impact" / "gate.py").read_text()
            self.assertEqual(copy, (fx.IMPACT_DIR / "gate.py").read_text())

    def test_P2_a_forged_merge_with_head_moved_cannot_reach_the_permissive_gate(self):
        for event, mg_base_key in (("pull_request", None), ("merge_group", "base")):
            with self.subTest(event=event):
                shas = self.build()
                self.hostile_move_head(self.forged_merge(shas))
                mg_base = shas[mg_base_key] if mg_base_key else ""
                self.assert_gate_fails_on_mismatch(
                    self.run_both(event, shas["p1"], shas["merge"], mg_base))
                self.fresh_repo()

    def test_P3_a_replace_ref_for_the_merge_commit_fails_closed(self):
        shas = self.build()
        self.hostile_replace(shas["merge"], self.forged_merge(shas))
        self.assert_gate_fails_on_mismatch(
            self.run_both("pull_request", shas["p1"], shas["merge"]))

    def test_P4_head_moved_onto_a_gateless_parent_never_bootstraps(self):
        shas = self.build()
        fx.git(self.repo, "checkout", "-q", "--detach", shas["c0"])
        forged = fx.commit_change(self.repo, {"forged.txt": "forged\n"})
        self.hostile_move_head(forged)
        self.assert_gate_fails_on_mismatch(
            self.run_both("pull_request", shas["p1"], shas["merge"]))

    def test_P8_a_replace_ref_on_the_merge_group_base_fails_closed(self):
        shas = self.build()
        self.hostile_replace(shas["base"], self.forged_merge(shas))
        self.assert_gate_fails_on_mismatch(
            self.run_both("merge_group", shas["p1"], shas["merge"], shas["base"]))

    def git_state_file(self, rel):
        """Absolute path of a file under the fixture's git dir (`rev-parse --git-path`)."""
        path = Path(fx.git(self.repo, "rev-parse", "--git-path", rel))
        path = path if path.is_absolute() else self.repo / path
        path.parent.mkdir(parents=True, exist_ok=True)
        return path

    def run_each_event(self, shas, extra_env=None):
        """Run both steps on both live events; assert every one fails closed."""
        for event, mg_base in (("pull_request", ""), ("merge_group", shas["base"])):
            with self.subTest(event=event):
                self.assert_gate_fails_on_mismatch(
                    self.run_both(event, shas["p1"], shas["merge"], mg_base, extra_env))

    def test_F3_a_grafts_file_that_reparents_the_merge_commit_fails_closed(self):
        """F3 / S15 grafts: with .git/info/grafts present both jobs used the PR's permissive gate."""
        shas = self.build()
        self.git_state_file("info/grafts").write_text(
            "%s %s %s\n" % (shas["merge"], shas["p0"], shas["p1"]))
        self.run_each_event(shas)

    def test_F3_a_replace_ref_is_refused_on_both_events(self):
        shas = self.build()
        self.hostile_replace(shas["c1"], self.forged_merge(shas))
        self.run_each_event(shas)

    def test_F3_an_alternates_file_is_refused_on_both_events(self):
        shas = self.build()
        self.git_state_file("objects/info/alternates").write_text(
            str(self.tmp / "other-objects") + "\n")
        self.run_each_event(shas)

    def test_F3_alternate_object_directories_in_the_environment_are_refused(self):
        shas = self.build()
        self.run_each_event(shas, {"GIT_ALTERNATE_OBJECT_DIRECTORIES": str(self.tmp / "other")})

    def test_F3_a_graft_file_in_the_environment_is_refused(self):
        shas = self.build()
        self.run_each_event(shas, {"GIT_GRAFT_FILE": str(self.tmp / "grafts")})

    def test_F3_a_shallow_checkout_is_refused_on_both_events(self):
        """fetch-depth 0 leaves no shallow file; one that exists is never accepted."""
        shas = self.build()
        self.git_state_file("shallow").write_text(shas["c0"] + "\n")
        self.run_each_event(shas)

    def test_F3_the_refusal_names_a_token_and_no_author_text(self):
        shas = self.build()
        self.git_state_file("info/grafts").write_text("%s %s\n" % (shas["merge"], shas["p0"]))
        results = self.run_both("pull_request", shas["p1"], shas["merge"])
        for job, (lines, summary) in results.items():
            with self.subTest(job=job):
                self.assertEqual(lines.get("reason"), "base-sha-mismatch")
                self.assertNotIn("forged", summary)

    def test_the_derivation_uses_the_github_sha_context_not_head(self):
        shas = self.build()
        for context in (shas["c1"], shas["p1"], "", "zz"):
            with self.subTest(context=context):
                self.assert_gate_fails_on_mismatch(
                    self.run_both("pull_request", shas["p1"], context))
        self.hostile_move_head(shas["p1"])
        self.assert_gate_fails_on_mismatch(
            self.run_both("pull_request", shas["p1"], shas["merge"]))

    def test_a_checkout_that_is_not_the_merge_ref_fails_closed(self):
        shas = self.build()
        fx.git(self.repo, "checkout", "-q", "main")
        self.assert_gate_fails_on_mismatch(
            self.run_both("pull_request", shas["p1"], shas["merge"]))

    def test_a_force_pushed_head_is_a_mismatch_not_a_bootstrap(self):
        shas = self.build()
        self.assert_gate_fails_on_mismatch(
            self.run_both("pull_request", shas["c1"], shas["merge"]))

    def test_a_malformed_merge_group_base_fails_closed_without_bootstrap(self):
        shas = self.build()
        for raw in ("", "--oops", "zz"):
            with self.subTest(raw=raw):
                results = self.run_both("merge_group", "", shas["merge"], raw)
                for job, (lines, summary) in results.items():
                    self.assertEqual(lines.get("reason"), "base-sha-invalid", summary)
                    self.assertNotEqual(lines.get("bootstrap"), "true", summary)

    def fresh_repo(self):
        shutil.rmtree(str(self.repo))
        shutil.rmtree(str(self.dest), ignore_errors=True)
        self.base = fx.init_repo(self.repo)

    def test_bootstrap_still_runs_when_the_derived_base_lacks_gate_py(self):
        shas = self.build()
        results = self.run_both("merge_group", shas["p1"], shas["merge"], shas["c0"])
        lines = results[GATE_JOB][0]
        self.assertEqual(lines.get("ok"), "false", results[GATE_JOB][1])
        self.assertEqual(lines.get("bootstrap"), "true", results[GATE_JOB][1])
        self.assertEqual(GateBaseRead.plan(self, lines), [BOOTSTRAP_STEP])

    def test_both_materialise_steps_carry_the_event_payload_for_the_derivation(self):
        for job, name in ((SELECT_JOB, MATERIALISE_STEP), (GATE_JOB, GATE_MATERIALISE_STEP)):
            env = step_named(job, name)["env"]
            with self.subTest(job=job):
                self.assertEqual(env["EVENT_NAME"], "${{ github.event_name }}")
                self.assertEqual(env["HEAD_SHA"], "${{ github.event.pull_request.head.sha"
                                 " || github.event.merge_group.head_sha }}")
                self.assertEqual(env["MERGE_GROUP_BASE_SHA"],
                                 "${{ github.event.merge_group.base_sha }}")
                self.assertEqual(env["CONTEXT_SHA"], CONTEXT_SHA_EXPR)
                self.assertIn("base-sha-mismatch", snippet_of(step_named(job, name)))


# code r12 C3 (round 15): the 180 workflow-level mutation forms of the security review of
# round 10 (119 forms of its first family, 61 of its second), carried as rows of this module so
# they run in both CI jobs on every push. Each form edits ci.yml text in memory (nothing is
# written to the checkout) and the module asserts the gate refuses it:
#   WF_FORM_RED    162 forms the pre-trust gate refuses; the value is the problem line it must
#                  report. A form marked REHASH changes a Materialise heredoc, so the sha256 pin
#                  is re-pinned to the mutated text and the second layer must refuse it alone.
#   WF_FORM_TESTS  9 forms another test of the gate suite refuses (this module, or the sibling
#                  module for the ci-gate job); the named tests run on the mutated text.
#   WF_FORM_GREEN  8 forms that stay green by design, each with its reason (controls, order
#                  insensitive sets, a move toward fail closed).
#   WF_FORM_DOC    1 form that reverts a docstring of this module to the banned wording.
# Round 16: k8-gate-timeout-value is refused by test_code_r13_f2_both_jobs_timeout_minutes_are_pinned
# (a failure; failing_tests_on_workflow counts failures only and raises on an error), and
# k8-select-name-value moved from WF_FORM_GREEN to WF_FORM_RED because the job names are pinned
# (sec r13 S2), so the counts are 162 / 9 / 8 / 1 (were 161 / 9 / 9 / 1).
# WF_FORM_SAME_AS names the 18 forms whose mutated text equals the text of a row that already
# exists in this module; they still run here, and a test asserts the text equality.


def _workflow_forms():
    """The reviewer's workflow-level mutation forms: id -> edits."""
    PIN = "11d5960a326750d5838078e36cf38b85af677262"
    OTHER = "08eba0b27e820071cde6df949e0beb9ba4906955"
    SEL_CO = (
        "      - uses: actions/checkout@%s # v4\n        with:\n          fetch-depth: 0\n          persist-credentials: false\n\n      #"
        " Skipping is off" % PIN
    )
    GATE_CO = (
        "      - uses: actions/checkout@%s # v4\n        with:\n          fetch-depth: 0\n          persist-credentials: false\n      #"
        " decision: on push, schedule" % PIN
    )
    CO_BLOCK = (
        "      - uses: actions/checkout@%s # v4\n        with:\n          fetch-depth: 0\n          persist-credentials: false\n" % PIN
    )
    MODE_NAME = "      - name: Selection mode\n"
    MODE_ENV = "        id: mode\n        env:\n          ENFORCE: ${{ vars.CI_IMPACT_ENFORCE }}\n"
    MODE_RUN = '        run: echo "enforce=${ENFORCE}" >> "$GITHUB_OUTPUT"\n'
    GATE_IF = (
        "        id: base\n        if: ${{ github.event_name == 'pull_request' || github.event_name"
        " == 'merge_group' }}\n        env:\n"
    )
    SEL_PY_END = "          PY\n\n      - name: Build impact index"
    GATE_PY_END = "          PY\n      # decision: !cancelled() &&"
    WF_ENV = "env:\n  CARGO_TERM_COLOR: always\n"
    SEL_JOB_ENV = "    timeout-minutes: 15\n    env:\n      RUSTUP_TOOLCHAIN: stable\n"
    GATE_HDR = "    runs-on: ubuntu-latest\n    timeout-minutes: 5\n    steps:\n"
    SEL_RUNSON = (
        "    # RUNNER PLACEMENT - GitHub-hosted: it only runs git and python.\n    runs-on:"
        " ubuntu-latest\n"
    )
    CONCURRENCY = re.compile("^concurrency:\\n(?:  .*\\n)+", re.M)
    ENV_KEYS = (
        "BASH_ENV",
        "ENV",
        "SHELLOPTS",
        "PATH",
        "LD_PRELOAD",
        "GIT_CONFIG_PARAMETERS",
        "GIT_DIR",
        "PYTHONPATH",
        "PYTHONSTARTUP",
    )
    IMPORTS = "          import sys\n          from pathlib import Path\n"
    MAIN = '          if __name__ == "__main__":\n'

    def rep(old, new, count=1):
        """Replace exactly `count` occurrences (count=0: all, at least one)."""

        def fn(text):
            n = text.count(old)
            if count and n != count or n == 0:
                raise ValueError(
                    "expected %s occurrence(s), found %d of %r" % (count or ">=1", n, old[:50])
                )
            return text.replace(old, new)

        return fn

    def rep_nth(old, new, nth):

        def fn(text):
            idx = -1
            for _ in range(nth):
                idx = text.index(old, idx + 1)
            return text[:idx] + new + text[idx + len(old) :]

        return fn

    def regex_sub(pattern, new):

        def fn(text):
            out, n = pattern.subn(new, text, count=1)
            if n != 1:
                raise ValueError("pattern not found")
            return out

        return fn

    def new_step(job, body):
        if job == "select":
            return rep(
                SEL_CO, SEL_CO.replace("\n\n      # Skipping", "\n\n" + body + "\n      # Skipping")
            )
        return rep(
            GATE_CO,
            GATE_CO.replace(
                "\n      # decision: on push", "\n" + body + "      # decision: on push"
            ),
        )

    def append_run(job, line):
        """Append a shell line to the Materialise `run: |` block after the heredoc end."""
        if job == "select":
            return rep(
                SEL_PY_END, "          PY\n          %s\n\n      - name: Build impact index" % line
            )
        return rep(
            GATE_PY_END, "          PY\n          %s\n      # decision: !cancelled() &&" % line
        )

    ANCHOR = "          GIT_TIMEOUT_S = 120\n"
    WF_PERM = "\npermissions:\n  contents: read\n"
    SEL_HDR = (
        "    # RUNNER PLACEMENT - GitHub-hosted: it only runs git and python.\n    runs-on:"
        " ubuntu-latest\n    timeout-minutes: 15\n"
    )
    SEL_CMT = "    # RUNNER PLACEMENT - GitHub-hosted: it only runs git and python.\n"
    GATE_TOP = "    name: ci-gate\n    if: always()\n"
    BUILD_IF = (
        "        if: ${{ steps.base.outputs.ok == 'true' }}\n        continue-on-error: true\n     "
        '   run: python3 -I "$RUNNER_TEMP/impact-base/impact/build_index.py"'
    )
    GATE_MAT_IF = (
        "        if: ${{ github.event_name == 'pull_request' || github.event_name == 'merge_group'"
        " }}\n"
    )
    BASE_FOLD_IF = (
        "        if: ${{ !cancelled() && (github.event_name == 'pull_request' || github.event_name"
        " == 'merge_group') && steps.base.outputs.ok == 'true' }}\n"
    )

    def heredoc_line(line):
        """Insert one module-level line after GIT_TIMEOUT_S in BOTH Materialise heredocs."""
        return [rep(ANCHOR, ANCHOR + "          " + line + "\n", 2), "REHASH"]

    m = {}
    m["r10-01-quoted-shell"] = [
        rep("        id: mode\n", '        id: mode\n        "shell": bash\n')
    ]
    m["r10-02-spaced-shell"] = [
        rep("        id: mode\n", "        id: mode\n        shell : bash\n")
    ]
    m["r10-03-flow-step-shell"] = [
        rep(
            MODE_NAME + MODE_ENV + MODE_RUN,
            "      - {name: Selection mode, id: mode, shell: bash, env: {ENFORCE: x}, run: echo}\n",
        )
    ]
    m["r10-04-block-scalar-shell"] = [
        rep(
            "        id: mode\n",
            "        id: mode\n        shell: |\n          bash --noprofile {0}\n",
        )
    ]
    m["r10-05-quoted-BASH_ENV"] = [rep(MODE_ENV, MODE_ENV + '          "BASH_ENV": ./x\n')]
    m["r10-06-spaced-BASH_ENV"] = [rep(MODE_ENV, MODE_ENV + "          BASH_ENV : ./x\n")]
    m["r10-07-flow-env-BASH_ENV"] = [
        rep(
            "        env:\n          ENFORCE: ${{ vars.CI_IMPACT_ENFORCE }}\n",
            '        env: {ENFORCE: "${{ vars.CI_IMPACT_ENFORCE }}", BASH_ENV: ./x}\n',
        )
    ]
    m["r10-08-quoted-submodules"] = [
        rep(
            SEL_CO,
            SEL_CO.replace("fetch-depth: 0\n", 'fetch-depth: 0\n          "submodules": true\n'),
        )
    ]
    m["r10-09-wf-BASH_ENV"] = [rep(WF_ENV, WF_ENV + "  BASH_ENV: ./x\n")]
    m["r10-10-job-BASH_ENV-select"] = [rep(SEL_JOB_ENV, SEL_JOB_ENV + "      BASH_ENV: ./x\n")]
    m["r10-11-job-BASH_ENV-gate"] = [
        rep(
            GATE_HDR,
            GATE_HDR.replace("    steps:\n", "    env:\n      BASH_ENV: ./x\n    steps:\n"),
        )
    ]
    m["r10-12-wf-defaults-shell"] = [
        rep("\njobs:\n", "\ndefaults:\n  run:\n    shell: bash --rcfile ./x -i {0}\n\njobs:\n")
    ]
    m["r10-13-job-defaults-wd-select"] = [
        rep(
            SEL_JOB_ENV,
            SEL_JOB_ENV + "    defaults:\n      run:\n        working-directory: scripts\n",
        )
    ]
    m["r10-14-wf-PYTHONPATH"] = [rep(WF_ENV, WF_ENV + "  PYTHONPATH: scripts/ci\n")]
    m["r10-15-wf-defaults-wd"] = [
        rep("\njobs:\n", "\ndefaults:\n  run:\n    working-directory: scripts\n\njobs:\n")
    ]
    m["r10-16-container-select"] = [rep(SEL_JOB_ENV, SEL_JOB_ENV + "    container: ubuntu:24.04\n")]
    m["r10-17-container-gate"] = [
        rep(GATE_HDR, GATE_HDR.replace("    steps:\n", "    container: ubuntu:24.04\n    steps:\n"))
    ]
    for job in ("select", "gate"):
        m["r10-f3-%s-append-base_sha" % job] = [
            append_run(job, "python3 scripts/ci/impact/base_sha.py")
        ]
        m["r10-f3-%s-append-source-env" % job] = [append_run(job, "source .env")]
        m["r10-f3-%s-append-dot-x" % job] = [append_run(job, "./x")]
    m["r10-f3-select-one-byte"] = [rep_nth("GIT_TIMEOUT_S = 120", "GIT_TIMEOUT_S = 121", 1)]
    m["r10-f3-gate-one-byte"] = [rep_nth("GIT_TIMEOUT_S = 120", "GIT_TIMEOUT_S = 121", 2)]
    m["l01-grafts-path-dropped"] = [
        rep(
            '("info/grafts", "shallow", "objects/info/alternates")',
            '("shallow", "objects/info/alternates")',
            2,
        )
    ]
    m["l02-shallow-path-dropped"] = [
        rep(
            '("info/grafts", "shallow", "objects/info/alternates")',
            '("info/grafts", "objects/info/alternates")',
            2,
        )
    ]
    m["l03-alternates-path-dropped"] = [
        rep(
            '("info/grafts", "shallow", "objects/info/alternates")', '("info/grafts", "shallow")', 2
        )
    ]
    m["l04-GIT_ALTERNATE_OBJECT_DIRECTORIES-dropped"] = [
        rep('("GIT_GRAFT_FILE", "GIT_ALTERNATE_OBJECT_DIRECTORIES",', '("GIT_GRAFT_FILE",', 2)
    ]
    m["l05-GIT_GRAFT_FILE-dropped"] = [
        rep(
            '("GIT_GRAFT_FILE", "GIT_ALTERNATE_OBJECT_DIRECTORIES",',
            '("GIT_ALTERNATE_OBJECT_DIRECTORIES",',
            2,
        )
    ]
    m["l06-git_state_refused-not-called"] = [
        rep("if replace_refs_present() or git_state_refused():", "if replace_refs_present():", 2)
    ]
    m["l07-select-make-prep"] = [new_step("select", "      - name: Prep\n        run: make prep\n")]
    m["l08-select-sh-c"] = [
        new_step("select", "      - name: Prep\n        run: sh -c ./ci/prep\n")
    ]
    m["l09-select-second-uses"] = [new_step("select", "      - uses: actions/cache@v4\n")]
    m["l10-select-checkout-sha"] = [rep(SEL_CO, SEL_CO.replace(PIN, OTHER))]
    m["l11-gate-make-prep"] = [new_step("gate", "      - name: Prep\n        run: make prep\n")]
    m["l12-gate-sh-c"] = [new_step("gate", "      - name: Prep\n        run: sh -c ./ci/prep\n")]
    m["l13-gate-second-uses"] = [new_step("gate", "      - uses: actions/cache@v4\n")]
    m["l14-ref-checkout-after-materialise"] = [
        rep(
            SEL_PY_END,
            "          PY\n\n      - uses: actions/checkout@%s # v4\n        with:\n          ref:"
            " ${{ github.event.pull_request.head.sha }}\n\n      - name: Build impact index" % PIN,
        )
    ]
    m["l15-plain-checkout-after-materialise"] = [
        rep(
            SEL_PY_END,
            "          PY\n\n      - uses: actions/checkout@%s # v4\n\n      - name: Build impact"
            " index" % PIN,
        )
    ]
    m["l16-BASH_ENV-selection-mode"] = [rep(MODE_ENV, MODE_ENV + "          BASH_ENV: ./x\n")]
    m["l17-shell-selection-mode"] = [
        rep("        id: mode\n", "        id: mode\n        shell: sh\n")
    ]
    m["l18-wd-selection-mode"] = [
        rep("        id: mode\n", "        id: mode\n        working-directory: scripts\n")
    ]
    m["l19-base_sha-run-step"] = [
        rep(
            MODE_RUN,
            MODE_RUN
            + "\n      - name: Report\n        run: python3 -I scripts/ci/impact/base_sha.py\n",
        )
    ]
    resolver = (
        "      - name: Resolve the live base (#8240)\n        id: live\n        run: python3 -I"
        " scripts/ci/impact/base_sha.py\n"
    )
    m["l20-resolver-in-select"] = [new_step("select", resolver)]
    m["l21-resolver-in-gate"] = [new_step("gate", resolver)]
    m["l22-GIT_NO_REPLACE_OBJECTS-dropped"] = [
        rep('env = dict(os.environ, GIT_NO_REPLACE_OBJECTS="1")', "env = dict(os.environ)", 2)
    ]
    m["l23-github.sha-replaced-by-HEAD"] = [
        rep('rev_parse(context + "^1^{commit}")', 'rev_parse("HEAD^1^{commit}")', 2)
    ]
    m["l24-script-appended-to-selection-mode"] = [
        rep(MODE_RUN, MODE_RUN.rstrip("\n") + " && bash scripts/ci/prep.bash\n")
    ]
    m["l25-replace-ref-check-dropped"] = [
        rep("if replace_refs_present() or git_state_refused():", "if git_state_refused():", 2)
    ]
    m["l26-replace-and-state-dropped"] = [
        rep(
            "                  if replace_refs_present() or git_state_refused():\n                 "
            '     raise BaseUnavailable("base-sha-mismatch")\n',
            "",
            2,
        )
    ]
    m["l27-HEAD-eq-context-dropped"] = [
        rep(
            'if not SHA_RE.match(context) or rev_parse("HEAD^{commit}") != context:',
            "if not SHA_RE.match(context):",
            2,
        )
    ]
    m["c1-single-quoted-shell"] = [
        rep("        id: mode\n", "        id: mode\n        'shell': bash\n")
    ]
    m["c1-quoted-with-plus-submodules"] = [
        rep(
            SEL_CO,
            SEL_CO.replace(
                "        with:\n          fetch-depth: 0\n",
                '        "with":\n          fetch-depth: 0\n          submodules: true\n',
            ),
        )
    ]
    m["c1-quoted-with-only-control"] = [
        rep(SEL_CO, SEL_CO.replace("        with:\n", '        "with":\n'))
    ]
    m["c1-spaced-submodules"] = [
        rep(
            SEL_CO,
            SEL_CO.replace("fetch-depth: 0\n", "fetch-depth: 0\n          submodules : true\n"),
        )
    ]
    m["c1-flow-with-submodules"] = [
        rep(
            SEL_CO,
            SEL_CO.replace(
                "        with:\n          fetch-depth: 0\n          persist-credentials: false\n",
                "        with: {fetch-depth: 0, submodules: true, persist-credentials: false}\n",
            ),
        )
    ]
    m["c1-folded-env-value"] = [
        rep(MODE_ENV, MODE_ENV + "          BASH_ENV: >\n            ./x\n")
    ]
    m["c1-literal-env-value"] = [
        rep(MODE_ENV, MODE_ENV + "          BASH_ENV: |-\n            ./x\n")
    ]
    m["c1-anchor-alias"] = [
        rep(WF_ENV, "env:\n  CARGO_TERM_COLOR: &a always\n"),
        rep(MODE_ENV, MODE_ENV + "          BASH_ENV: *a\n"),
    ]
    m["c1-anchor-on-mapping-merge"] = [
        rep(WF_ENV, "env: &wf\n  CARGO_TERM_COLOR: always\n"),
        rep(MODE_ENV, MODE_ENV.replace("        env:\n", "        env:\n          <<: *wf\n")),
    ]
    m["c1-merge-key-flow"] = [rep(MODE_ENV, MODE_ENV + "          <<: {BASH_ENV: ./x}\n")]
    m["c1-escaped-key"] = [rep(MODE_ENV, MODE_ENV + '          "BASH\\u005fENV": ./x\n')]
    m["c1-tab-after-colon"] = [rep(MODE_ENV, MODE_ENV + "          BASH_ENV:\t./x\n")]
    m["c1-tab-before-colon"] = [rep(MODE_ENV, MODE_ENV + "          BASH_ENV\t: ./x\n")]
    m["c1-job-env-flow"] = [
        rep(
            SEL_JOB_ENV,
            "    timeout-minutes: 15\n    env: {RUSTUP_TOOLCHAIN: stable, BASH_ENV: ./x}\n",
        )
    ]
    m["c1-wf-env-quoted"] = [rep(WF_ENV, WF_ENV + "  'BASH_ENV': ./x\n")]
    m["c1-trailing-comment-key"] = [rep(MODE_ENV, MODE_ENV + "          BASH_ENV: ./x # note\n")]
    m["c1-explicit-tag-value"] = [rep(MODE_ENV, MODE_ENV + "          BASH_ENV: !!str ./x\n")]
    for key in ENV_KEYS:
        m["c2-wf-env-" + key] = [rep(WF_ENV, WF_ENV + "  %s: ./x\n" % key)]
    m["c2-container-image-options"] = [
        rep(
            SEL_JOB_ENV,
            SEL_JOB_ENV + "    container:\n      image: ubuntu:24.04\n      options: --user 0\n",
        )
    ]
    m["c2-services-select"] = [
        rep(SEL_JOB_ENV, SEL_JOB_ENV + "    services:\n      db:\n        image: postgres:18\n")
    ]
    m["c2-job-defaults-shell-gate"] = [
        rep(
            GATE_HDR,
            GATE_HDR.replace(
                "    steps:\n", "    defaults:\n      run:\n        shell: sh\n    steps:\n"
            ),
        )
    ]
    m["c2-job-env-gate-benign"] = [
        rep(GATE_HDR, GATE_HDR.replace("    steps:\n", "    env:\n      FOO: bar\n    steps:\n"))
    ]
    m["c2-runs-on-self-hosted-select"] = [
        rep(SEL_RUNSON, SEL_RUNSON.replace("ubuntu-latest", "[self-hosted, linux]"))
    ]
    m["c2-runs-on-self-hosted-gate"] = [
        rep(GATE_HDR, GATE_HDR.replace("ubuntu-latest", "[self-hosted, linux]"))
    ]
    m["c2-permissions-select"] = [
        rep(
            SEL_JOB_ENV,
            SEL_JOB_ENV + "    permissions:\n      contents: write\n      id-token: write\n",
        )
    ]
    m["c2-concurrency-removed"] = [regex_sub(CONCURRENCY, "")]
    for job in ("select", "gate"):
        for tag, line in (
            ("py-c", "python3 -c 'import runpy'"),
            ("source", "source ./x"),
            ("dot", ". ./x"),
            ("exec", "exec ./x"),
            ("eval", 'eval "$X"'),
            ("cmdsub", "echo $(./x)"),
            ("backtick", "echo `./x`"),
            ("procsub", "bash <(cat x)"),
            ("hookspath", "git -c core.hooksPath=h status"),
            ("alias", "git -c alias.x='!sh' x"),
            ("rebase-exec", "git rebase --exec make HEAD~1"),
            ("ssh-command", "GIT_SSH_COMMAND=make git fetch"),
        ):
            m["c3-%s-%s" % (job, tag)] = [append_run(job, line)]
    stale = {
        "x8-runpy": (
            IMPORTS.replace("import sys\n", "import sys\n          import runpy\n")
            + "          os.path.exists('scripts/ci/prep.py') and"
            " runpy.run_path('scripts/ci/prep.py')\n"
        ),
        "check-call-make": IMPORTS + '          subprocess.check_call(["make", "prep"])\n',
        "getoutput": IMPORTS + '          subprocess.getoutput("make prep")\n',
        "posix-spawnp": IMPORTS + '          os.posix_spawnp("make", ["make"], dict(os.environ))\n',
        "call-bare-file": IMPORTS + '          subprocess.call(["sh", "prep.bash"])\n',
        "relative-dotfile": IMPORTS + '          subprocess.call(["sh", ".prep"])\n',
    }
    for tag, new in stale.items():
        m["sh-" + tag] = [rep(IMPORTS, new, 2), "REHASH"]
    m["sh-git-fsmonitor"] = [
        rep(MAIN, '          git("-c", "core.fsmonitor=make", "status")\n\n\n' + MAIN, 2),
        "REHASH",
    ]
    m["sh-git-alias"] = [
        rep(MAIN, '          git("-c", "alias.p=!make", "p")\n\n\n' + MAIN, 2),
        "REHASH",
    ]
    m["c2-baseline-unmutated"] = []
    m["f2-select-mat-env-value"] = [
        rep_nth(
            "          CONTEXT_SHA: ${{ github.sha }}\n",
            "          CONTEXT_SHA: ${{ github.ref }}\n",
            1,
        )
    ]
    m["f2-gate-mat-env-value"] = [
        rep_nth(
            "          CONTEXT_SHA: ${{ github.sha }}\n",
            "          CONTEXT_SHA: ${{ github.ref }}\n",
            2,
        )
    ]
    m["f2-gate-impact-files-value"] = [
        rep(
            "IMPACT_FILES: __init__.py common.py gate.py rules.json\n",
            "IMPACT_FILES: __init__.py common.py gate.py rules.json x.py\n",
        )
    ]
    m["f2-gate-fold-env-value"] = [
        rep_nth(
            "          GITHUB_REF_NAME_FULL: ${{ github.ref }}\n",
            "          GITHUB_REF_NAME_FULL: refs/heads/main\n",
            1,
        )
    ]
    m["f2-select-mode-env-value"] = [
        rep_nth("ENFORCE: ${{ vars.CI_IMPACT_ENFORCE }}\n", "ENFORCE: 'true'\n", 1)
    ]
    m["f2-wf-env-value"] = [rep("  CARGO_TERM_COLOR: always\n", "  CARGO_TERM_COLOR: never\n")]
    m["f2-select-job-env-value"] = [
        rep("      RUSTUP_TOOLCHAIN: stable\n", "      RUSTUP_TOOLCHAIN: nightly\n")
    ]
    m["f2-select-jobkey-strategy"] = [
        rep(SEL_HDR, SEL_HDR + "    strategy:\n      matrix:\n        x: [a]\n")
    ]
    m["f2-select-jobkey-continue-on-error"] = [
        rep(SEL_HDR, SEL_HDR + "    continue-on-error: true\n")
    ]
    m["f2-select-jobkey-environment"] = [rep(SEL_HDR, SEL_HDR + "    environment: release\n")]
    m["f2-gate-jobkey-concurrency"] = [
        rep(GATE_HDR, GATE_HDR.replace("    steps:\n", "    concurrency: x\n    steps:\n"))
    ]
    m["f2-gate-jobkey-strategy"] = [
        rep(
            GATE_HDR,
            GATE_HDR.replace(
                "    steps:\n", "    strategy:\n      matrix:\n        x: [a]\n    steps:\n"
            ),
        )
    ]
    m["f2-select-key-missing-timeout"] = [rep(SEL_HDR, SEL_CMT + "    runs-on: ubuntu-latest\n")]
    m["f2-gate-key-missing-timeout"] = [rep(GATE_HDR, "    runs-on: ubuntu-latest\n    steps:\n")]
    m["f2-select-runs-on-self-hosted"] = [
        rep(SEL_HDR, SEL_HDR.replace("ubuntu-latest", "[self-hosted, linux]"))
    ]
    m["f2-gate-runs-on-self-hosted"] = [
        rep(GATE_HDR, GATE_HDR.replace("ubuntu-latest", "self-hosted"))
    ]
    m["f2-select-runs-on-group"] = [rep(SEL_HDR, SEL_HDR.replace("ubuntu-latest", "{group: big}"))]
    m["f2-wf-perm-contents-write"] = [rep(WF_PERM, "\npermissions:\n  contents: write\n")]
    m["f2-wf-perm-add-scope"] = [rep(WF_PERM, WF_PERM + "  id-token: write\n")]
    m["f2-wf-perm-write-all"] = [rep(WF_PERM, "\npermissions: write-all\n")]
    m["f2-wf-perm-removed"] = [rep(WF_PERM, "\n")]
    m["f2-select-perm-contents-write"] = [
        rep(SEL_HDR, SEL_HDR + "    permissions:\n      contents: write\n")
    ]
    m["f2-select-perm-add-scope"] = [
        rep(SEL_HDR, SEL_HDR + "    permissions:\n      contents: read\n      id-token: write\n")
    ]
    m["f2-gate-perm-write-all"] = [
        rep(GATE_HDR, GATE_HDR.replace("    steps:\n", "    permissions: write-all\n    steps:\n"))
    ]
    m["f2-reorder-select-job-keys"] = [
        rep(SEL_HDR, SEL_CMT + "    timeout-minutes: 15\n    runs-on: ubuntu-latest\n")
    ]
    m["f2-reorder-gate-job-keys"] = [
        rep(GATE_HDR, "    timeout-minutes: 5\n    runs-on: ubuntu-latest\n    steps:\n")
    ]
    m["f2-reorder-wf-env"] = [
        rep(
            "env:\n  CARGO_TERM_COLOR: always\n",
            'env:\n  CARGO_INCREMENTAL: "0"\n  CARGO_TERM_COLOR: always\n',
        ),
        rep('  CARGO_INCREMENTAL: "0"\n\njobs:\n', "\njobs:\n"),
    ]
    m["f2-reorder-mat-env"] = [
        rep("          CONTEXT_SHA: ${{ github.sha }}\n", "", 2),
        rep(
            "          IMPACT_FILES:",
            "          CONTEXT_SHA: ${{ github.sha }}\n          IMPACT_FILES:",
            2,
        ),
    ]
    m["c2-sh-getoutput"] = heredoc_line('subprocess.getoutput("make prep")')
    m["c2-sh-posix-spawnp"] = heredoc_line('os.posix_spawnp("make", ["make"], dict(os.environ))')
    m["c2-sh-call-bare-file"] = heredoc_line('subprocess.call(["sh", "prep.bash"])')
    m["c2-sh-git-alias"] = heredoc_line('git("-c", "alias.p=!make", "p")')
    m["c2-sh-git-fsmonitor"] = heredoc_line('git("-c", "core.fsmonitor=make", "status")')
    m["c2-git-c-hookspath"] = heredoc_line('git("-c", "core.hooksPath=h", "fetch")')
    m["c2-second-subprocess-run"] = heredoc_line('subprocess.run(["make", "prep"])')
    m["c2-argv0-variable"] = heredoc_line('ARGV = ["make"]')[:1] + [
        rep(
            'subprocess.run(["git", "--no-replace-objects"] + list(args),',
            "subprocess.run(ARGV + list(args),",
            2,
        ),
        "REHASH",
    ]
    m["c2-shutil-which-git"] = heredoc_line('GIT = shutil.which("git")')
    m["c2x-module-alias-call"] = heredoc_line('sp = subprocess; sp.getoutput("make prep")')
    m["c2x-method-on-constant-dash"] = heredoc_line(
        'git("fetch", "x--upload-pack=make".lstrip("x"), "origin")'
    )
    m["c2x-environ-subscript-store"] = heredoc_line('os.environ["GIT_CONFIG_COUNT"] = "1"')
    m["c2x-path-method-write"] = heredoc_line('Path("x.git".lstrip("x"), "config").open("a")')
    m["k8-build-index-if-pr-data"] = [
        rep(
            BUILD_IF,
            BUILD_IF.replace(
                "steps.base.outputs.ok == 'true'", "github.event.pull_request.title != ''"
            ),
        )
    ]
    m["k8-build-index-coe-false"] = [
        rep(BUILD_IF, BUILD_IF.replace("continue-on-error: true", "continue-on-error: false"))
    ]
    m["k8-gate-materialise-if-false"] = [rep(GATE_MAT_IF, "        if: ${{ false }}\n")]
    m["k8-base-fold-if-false"] = [rep(BASE_FOLD_IF, "        if: ${{ false }}\n")]
    m["k8-gate-job-if-false"] = [rep(GATE_TOP, "    name: ci-gate\n    if: ${{ false }}\n")]
    m["k8-gate-job-if-success"] = [rep(GATE_TOP, "    name: ci-gate\n    if: success()\n")]
    m["k8-gate-needs-drop-check"] = [
        rep(
            "      - mobile-cross-compile\n    # RUNNER PLACEMENT - GitHub-hosted: it only reads",
            "    # RUNNER PLACEMENT - GitHub-hosted: it only reads",
        )
    ]
    m["k8-select-output-literal"] = [
        rep(
            "      rust: ${{ steps.select.outputs.rust || steps.fallback.outputs.rust }}\n",
            "      rust: 'false'\n",
        )
    ]
    m["k8-gate-timeout-value"] = [
        rep(GATE_HDR, GATE_HDR.replace("timeout-minutes: 5", "timeout-minutes: 600"))
    ]
    m["k8-select-name-value"] = [
        rep("    name: Impact selection\n", "    name: Impact selection x\n")
    ]
    m["k8-mode-step-continue-on-error"] = [
        rep("        id: mode\n", "        id: mode\n        continue-on-error: true\n")
    ]
    m["k8-mode-step-timeout"] = [
        rep("        id: mode\n", "        id: mode\n        timeout-minutes: 1\n")
    ]
    m["k8-mode-step-if-pr-data"] = [
        rep(
            "        id: mode\n",
            "        id: mode\n        if: ${{ github.event.pull_request.title != '' }}\n",
        )
    ]
    m["k8-select-job-uses-reusable"] = [
        rep(SEL_HDR, SEL_HDR + "    uses: ./.github/workflows/x.yml\n")
    ]
    m["k8-container-credentials"] = [
        rep(
            SEL_HDR,
            SEL_HDR + "    container:\n      image: x\n      credentials:\n        username: u\n",
        )
    ]
    m["k8-services-gate"] = [
        rep(
            GATE_HDR,
            GATE_HDR.replace(
                "    steps:\n", "    services:\n      db:\n        image: x\n    steps:\n"
            ),
        )
    ]
    m["k8-checkout-with-ref"] = [
        rep(SEL_CO, SEL_CO.replace("fetch-depth: 0\n", "fetch-depth: 0\n          ref: x\n"))
    ]
    m["k8-checkout-with-persist"] = [
        rep(
            SEL_CO,
            SEL_CO.replace("persist-credentials: false", "persist-credentials: true"),
        )
    ]
    m["w1-docstring-reverted"] = ["DOCSTRING_REVERT"]
    m["w1-ci-comment-reverted"] = [
        rep_nth(
            "      # this step derives the base inline and no resolver script runs over\n",
            "      # the resolver is demoted to a post-" + "derivation report over\n",
            1,
        )
    ]
    return m

WF_FORM_RED = {
    "k8-select-name-value": "job select name",
    "r10-01-quoted-shell": (
        "job select step 'Selection mode' keys ['env', 'id', 'name', 'run', 'shell'], expected"
        " ['env', 'id', 'name', 'run']"
    ),
    "r10-02-spaced-shell": (
        "job select step 'Selection mode' keys ['env', 'id', 'name', 'run', 'shell'], expected"
        " ['env', 'id', 'name', 'run']"
    ),
    "r10-03-flow-step-shell": (
        "job select step 'Selection mode' keys ['env', 'id', 'name', 'run', 'shell'], expected"
        " ['env', 'id', 'name', 'run']"
    ),
    "r10-04-block-scalar-shell": (
        "job select step 'Selection mode' keys ['env', 'id', 'name', 'run', 'shell'], expected"
        " ['env', 'id', 'name', 'run']"
    ),
    "r10-05-quoted-BASH_ENV": "job select step 'Selection mode' inherits env BASH_ENV",
    "r10-06-spaced-BASH_ENV": "job select step 'Selection mode' inherits env BASH_ENV",
    "r10-07-flow-env-BASH_ENV": "job select step 'Selection mode' inherits env BASH_ENV",
    "r10-08-quoted-submodules": (
        "job select step None with {'fetch-depth': '0', 'submodules': 'true',"
        " 'persist-credentials': 'false'}, expected {'fetch-depth': '0', 'persist-credentials': 'false'}"
    ),
    "r10-09-wf-BASH_ENV": "workflow env sets BASH_ENV",
    "r10-10-job-BASH_ENV-select": "job select env sets BASH_ENV",
    "r10-11-job-BASH_ENV-gate": (
        "job ci-gate keys ['env', 'if', 'name', 'needs', 'runs-on', 'steps', 'timeout-minutes'],"
        " expected ['if', 'name', 'needs', 'runs-on', 'steps', 'timeout-minutes']"
    ),
    "r10-12-wf-defaults-shell": "workflow sets defaults",
    "r10-13-job-defaults-wd-select": "job select sets defaults",
    "r10-14-wf-PYTHONPATH": "workflow env sets PYTHONPATH",
    "r10-15-wf-defaults-wd": "workflow sets defaults",
    "r10-16-container-select": "job select sets container",
    "r10-17-container-gate": "job ci-gate sets container",
    "r10-f3-select-append-base_sha": "run text sha256",
    "r10-f3-select-append-source-env": "run text sha256",
    "r10-f3-select-append-dot-x": "run text sha256",
    "r10-f3-gate-append-base_sha": "run text sha256",
    "r10-f3-gate-append-source-env": "run text sha256",
    "r10-f3-gate-append-dot-x": "run text sha256",
    "r10-f3-select-one-byte": "run text sha256",
    "r10-f3-gate-one-byte": "run text sha256",
    "l01-grafts-path-dropped": "run text sha256",
    "l02-shallow-path-dropped": "run text sha256",
    "l03-alternates-path-dropped": "run text sha256",
    "l04-GIT_ALTERNATE_OBJECT_DIRECTORIES-dropped": "run text sha256",
    "l05-GIT_GRAFT_FILE-dropped": "run text sha256",
    "l06-git_state_refused-not-called": "run text sha256",
    "l07-select-make-prep": (
        "job select pre-trust steps are [None, 'Prep', 'Selection mode', 'Materialise the base"
        " selector (#8240)', 'Build impact index'], expected [None, 'Selection mode', 'Materialise"
        " the base selector (#8240)', 'Build impact index']"
    ),
    "l08-select-sh-c": (
        "job select pre-trust steps are [None, 'Prep', 'Selection mode', 'Materialise the base"
        " selector (#8240)', 'Build impact index'], expected [None, 'Selection mode', 'Materialise"
        " the base selector (#8240)', 'Build impact index']"
    ),
    "l09-select-second-uses": (
        "job select pre-trust steps are [None, None, 'Selection mode', 'Materialise the base"
        " selector (#8240)', 'Build impact index'], expected [None, 'Selection mode', 'Materialise"
        " the base selector (#8240)', 'Build impact index']"
    ),
    "l10-select-checkout-sha": (
        "job select step None uses 'actions/checkout@08eba0b27e820071cde6df949e0beb9ba4906955'"
    ),
    "l11-gate-make-prep": (
        "job ci-gate pre-trust steps are [None, 'Prep', 'Materialise the base gate (#8240)', 'Fold"
        " job results (base gate)'], expected [None, 'Materialise the base gate (#8240)', 'Fold job"
        " results (base gate)']"
    ),
    "l12-gate-sh-c": (
        "job ci-gate pre-trust steps are [None, 'Prep', 'Materialise the base gate (#8240)', 'Fold"
        " job results (base gate)'], expected [None, 'Materialise the base gate (#8240)', 'Fold job"
        " results (base gate)']"
    ),
    "l13-gate-second-uses": (
        "job ci-gate pre-trust steps are [None, None, 'Materialise the base gate (#8240)', 'Fold"
        " job results (base gate)'], expected [None, 'Materialise the base gate (#8240)', 'Fold job"
        " results (base gate)']"
    ),
    "l14-ref-checkout-after-materialise": (
        "job select pre-trust steps are [None, 'Selection mode', 'Materialise the base selector"
        " (#8240)', None, 'Build impact index'], expected [None, 'Selection mode', 'Materialise the"
        " base selector (#8240)', 'Build impact index']"
    ),
    "l15-plain-checkout-after-materialise": (
        "job select pre-trust steps are [None, 'Selection mode', 'Materialise the base selector"
        " (#8240)', None, 'Build impact index'], expected [None, 'Selection mode', 'Materialise the"
        " base selector (#8240)', 'Build impact index']"
    ),
    "l16-BASH_ENV-selection-mode": "job select step 'Selection mode' inherits env BASH_ENV",
    "l17-shell-selection-mode": (
        "job select step 'Selection mode' keys ['env', 'id', 'name', 'run', 'shell'], expected"
        " ['env', 'id', 'name', 'run']"
    ),
    "l18-wd-selection-mode": (
        "job select step 'Selection mode' keys ['env', 'id', 'name', 'run', 'working-directory'],"
        " expected ['env', 'id', 'name', 'run']"
    ),
    "l19-base_sha-run-step": (
        "job select pre-trust steps are [None, 'Selection mode', 'Report', 'Materialise the base"
        " selector (#8240)', 'Build impact index'], expected [None, 'Selection mode', 'Materialise"
        " the base selector (#8240)', 'Build impact index']"
    ),
    "l20-resolver-in-select": (
        "job select pre-trust steps are [None, 'Resolve the live base (#8240)', 'Selection mode',"
        " 'Materialise the base selector (#8240)', 'Build impact index'], expected [None,"
        " 'Selection mode', 'Materialise the base selector (#8240)', 'Build impact index']"
    ),
    "l21-resolver-in-gate": (
        "job ci-gate pre-trust steps are [None, 'Resolve the live base (#8240)', 'Materialise the"
        " base gate (#8240)', 'Fold job results (base gate)'], expected [None, 'Materialise the"
        " base gate (#8240)', 'Fold job results (base gate)']"
    ),
    "l22-GIT_NO_REPLACE_OBJECTS-dropped": "run text sha256",
    "l23-github.sha-replaced-by-HEAD": "run text sha256",
    "l24-script-appended-to-selection-mode": (
        "job select step 'Selection mode' run text differs from the allow-list"
    ),
    "l25-replace-ref-check-dropped": "run text sha256",
    "l26-replace-and-state-dropped": "run text sha256",
    "l27-HEAD-eq-context-dropped": "run text sha256",
    "c1-single-quoted-shell": (
        "job select step 'Selection mode' keys ['env', 'id', 'name', 'run', 'shell'], expected"
        " ['env', 'id', 'name', 'run']"
    ),
    "c1-quoted-with-plus-submodules": (
        "job select step None with {'fetch-depth': '0', 'submodules': 'true',"
        " 'persist-credentials': 'false'}, expected {'fetch-depth': '0', 'persist-credentials': 'false'}"
    ),
    "c1-spaced-submodules": (
        "job select step None with {'fetch-depth': '0', 'submodules': 'true',"
        " 'persist-credentials': 'false'}, expected {'fetch-depth': '0', 'persist-credentials': 'false'}"
    ),
    "c1-flow-with-submodules": (
        "job select step None with {'fetch-depth': '0', 'submodules': 'true',"
        " 'persist-credentials': 'false'}, expected {'fetch-depth': '0', 'persist-credentials': 'false'}"
    ),
    "c1-folded-env-value": "job select step 'Selection mode' inherits env BASH_ENV",
    "c1-literal-env-value": "job select step 'Selection mode' inherits env BASH_ENV",
    "c1-anchor-alias": (
        "workflow is unreadable by the strict loader: anchor, alias, tag or merge key"
    ),
    "c1-anchor-on-mapping-merge": (
        "workflow is unreadable by the strict loader: anchor, alias, tag or merge key"
    ),
    "c1-merge-key-flow": "workflow is unreadable by the strict loader: duplicate or merge key '<<'",
    "c1-escaped-key": (
        "workflow is unreadable by the strict loader: unsupported escape in a double-quoted scalar"
    ),
    "c1-tab-after-colon": (
        "workflow is unreadable by the strict loader: not a mapping entry (multi-line plain"
        " scalar?)"
    ),
    "c1-tab-before-colon": "job select step 'Selection mode' inherits env BASH_ENV",
    "c1-job-env-flow": "job select env sets BASH_ENV",
    "c1-wf-env-quoted": "workflow env sets BASH_ENV",
    "c1-trailing-comment-key": "job select step 'Selection mode' inherits env BASH_ENV",
    "c1-explicit-tag-value": (
        "workflow is unreadable by the strict loader: anchor, alias, tag or merge key"
    ),
    "c2-wf-env-BASH_ENV": "workflow env sets BASH_ENV",
    "c2-wf-env-ENV": "workflow env sets ENV",
    "c2-wf-env-SHELLOPTS": "workflow env sets SHELLOPTS",
    "c2-wf-env-PATH": "workflow env sets PATH",
    "c2-wf-env-LD_PRELOAD": "workflow env sets LD_PRELOAD",
    "c2-wf-env-GIT_CONFIG_PARAMETERS": "workflow env sets GIT_CONFIG_PARAMETERS",
    "c2-wf-env-GIT_DIR": "workflow env sets GIT_DIR",
    "c2-wf-env-PYTHONPATH": "workflow env sets PYTHONPATH",
    "c2-wf-env-PYTHONSTARTUP": "workflow env sets PYTHONSTARTUP",
    "c2-container-image-options": "job select sets container",
    "c2-services-select": "job select sets services",
    "c2-job-defaults-shell-gate": "job ci-gate sets defaults",
    "c2-job-env-gate-benign": (
        "job ci-gate keys ['env', 'if', 'name', 'needs', 'runs-on', 'steps', 'timeout-minutes'],"
        " expected ['if', 'name', 'needs', 'runs-on', 'steps', 'timeout-minutes']"
    ),
    "c2-runs-on-self-hosted-select": (
        "job select runs-on ['self-hosted', 'linux'], expected 'ubuntu-latest'"
    ),
    "c2-runs-on-self-hosted-gate": (
        "job ci-gate runs-on ['self-hosted', 'linux'], expected 'ubuntu-latest'"
    ),
    "c2-permissions-select": (
        "job select keys ['env', 'name', 'outputs', 'permissions', 'runs-on', 'steps',"
        " 'timeout-minutes'], expected ['env', 'name', 'outputs', 'runs-on', 'steps',"
        " 'timeout-minutes']"
    ),
    "c3-select-py-c": "run text sha256",
    "c3-select-source": "run text sha256",
    "c3-select-dot": "run text sha256",
    "c3-select-exec": "run text sha256",
    "c3-select-eval": "run text sha256",
    "c3-select-cmdsub": "run text sha256",
    "c3-select-backtick": "run text sha256",
    "c3-select-procsub": "run text sha256",
    "c3-select-hookspath": "run text sha256",
    "c3-select-alias": "run text sha256",
    "c3-select-rebase-exec": "run text sha256",
    "c3-select-ssh-command": "run text sha256",
    "c3-gate-py-c": "run text sha256",
    "c3-gate-source": "run text sha256",
    "c3-gate-dot": "run text sha256",
    "c3-gate-exec": "run text sha256",
    "c3-gate-eval": "run text sha256",
    "c3-gate-cmdsub": "run text sha256",
    "c3-gate-backtick": "run text sha256",
    "c3-gate-procsub": "run text sha256",
    "c3-gate-hookspath": "run text sha256",
    "c3-gate-alias": "run text sha256",
    "c3-gate-rebase-exec": "run text sha256",
    "c3-gate-ssh-command": "run text sha256",
    "sh-x8-runpy": "import statement outside the pinned set (import runpy)",
    "sh-check-call-make": "calls subprocess.check_call outside the allow-list",
    "sh-getoutput": "calls subprocess.getoutput outside the allow-list",
    "sh-posix-spawnp": "calls os.posix_spawnp outside the allow-list",
    "sh-call-bare-file": "calls subprocess.call outside the allow-list",
    "sh-relative-dotfile": "calls subprocess.call outside the allow-list",
    "sh-git-fsmonitor": "git call with a subcommand outside the allow-list",
    "sh-git-alias": "git call with a subcommand outside the allow-list",
    "f2-select-mat-env-value": (
        "job select step 'Materialise the base selector (#8240)' env values differ from the pinned"
        " mapping"
    ),
    "f2-gate-mat-env-value": (
        "job ci-gate step 'Materialise the base gate (#8240)' env values differ from the pinned"
        " mapping"
    ),
    "f2-gate-impact-files-value": (
        "job ci-gate step 'Materialise the base gate (#8240)' env values differ from the pinned"
        " mapping"
    ),
    "f2-gate-fold-env-value": (
        "job ci-gate step 'Fold job results (base gate)' env values differ from the pinned mapping"
    ),
    "f2-select-mode-env-value": (
        "job select step 'Selection mode' env values differ from the pinned mapping"
    ),
    "f2-wf-env-value": "workflow env differs from the pinned key/value mapping",
    "f2-select-job-env-value": "job select env differs from the pinned key/value mapping",
    "f2-select-jobkey-strategy": (
        "job select keys ['env', 'name', 'outputs', 'runs-on', 'steps', 'strategy',"
        " 'timeout-minutes'], expected ['env', 'name', 'outputs', 'runs-on', 'steps',"
        " 'timeout-minutes']"
    ),
    "f2-select-jobkey-continue-on-error": (
        "job select keys ['continue-on-error', 'env', 'name', 'outputs', 'runs-on', 'steps',"
        " 'timeout-minutes'], expected ['env', 'name', 'outputs', 'runs-on', 'steps',"
        " 'timeout-minutes']"
    ),
    "f2-select-jobkey-environment": (
        "job select keys ['env', 'environment', 'name', 'outputs', 'runs-on', 'steps',"
        " 'timeout-minutes'], expected ['env', 'name', 'outputs', 'runs-on', 'steps',"
        " 'timeout-minutes']"
    ),
    "f2-gate-jobkey-concurrency": (
        "job ci-gate keys ['concurrency', 'if', 'name', 'needs', 'runs-on', 'steps',"
        " 'timeout-minutes'], expected ['if', 'name', 'needs', 'runs-on', 'steps',"
        " 'timeout-minutes']"
    ),
    "f2-gate-jobkey-strategy": (
        "job ci-gate keys ['if', 'name', 'needs', 'runs-on', 'steps', 'strategy',"
        " 'timeout-minutes'], expected ['if', 'name', 'needs', 'runs-on', 'steps',"
        " 'timeout-minutes']"
    ),
    "f2-select-key-missing-timeout": (
        "job select keys ['env', 'name', 'outputs', 'runs-on', 'steps'], expected ['env', 'name',"
        " 'outputs', 'runs-on', 'steps', 'timeout-minutes']"
    ),
    "f2-gate-key-missing-timeout": (
        "job ci-gate keys ['if', 'name', 'needs', 'runs-on', 'steps'], expected ['if', 'name',"
        " 'needs', 'runs-on', 'steps', 'timeout-minutes']"
    ),
    "f2-select-runs-on-self-hosted": (
        "job select runs-on ['self-hosted', 'linux'], expected 'ubuntu-latest'"
    ),
    "f2-gate-runs-on-self-hosted": "job ci-gate runs-on 'self-hosted', expected 'ubuntu-latest'",
    "f2-select-runs-on-group": "job select runs-on {'group': 'big'}, expected 'ubuntu-latest'",
    "f2-wf-perm-contents-write": "workflow permissions differ from the pinned mapping",
    "f2-wf-perm-add-scope": "workflow permissions differ from the pinned mapping",
    "f2-wf-perm-write-all": "workflow permissions differ from the pinned mapping",
    "f2-wf-perm-removed": "workflow permissions differ from the pinned mapping",
    "f2-select-perm-contents-write": (
        "job select keys ['env', 'name', 'outputs', 'permissions', 'runs-on', 'steps',"
        " 'timeout-minutes'], expected ['env', 'name', 'outputs', 'runs-on', 'steps',"
        " 'timeout-minutes']"
    ),
    "f2-select-perm-add-scope": (
        "job select keys ['env', 'name', 'outputs', 'permissions', 'runs-on', 'steps',"
        " 'timeout-minutes'], expected ['env', 'name', 'outputs', 'runs-on', 'steps',"
        " 'timeout-minutes']"
    ),
    "f2-gate-perm-write-all": (
        "job ci-gate keys ['if', 'name', 'needs', 'permissions', 'runs-on', 'steps',"
        " 'timeout-minutes'], expected ['if', 'name', 'needs', 'runs-on', 'steps',"
        " 'timeout-minutes']"
    ),
    "c2-sh-getoutput": "calls subprocess.getoutput outside the allow-list",
    "c2-sh-posix-spawnp": "calls os.posix_spawnp outside the allow-list",
    "c2-sh-call-bare-file": "calls subprocess.call outside the allow-list",
    "c2-sh-git-alias": "git call with a subcommand outside the allow-list",
    "c2-sh-git-fsmonitor": "git call with a subcommand outside the allow-list",
    "c2-git-c-hookspath": "git call with a subcommand outside the allow-list",
    "c2-second-subprocess-run": "subprocess.run argv is not the exact git head plus list(args)",
    "c2-argv0-variable": "module-level binding of ARGV outside the pinned module stores",
    "c2-shutil-which-git": "module-level binding of GIT outside the pinned module stores",
    "c2x-module-alias-call": "module-level binding of sp outside the pinned module stores",
    "c2x-method-on-constant-dash": "git argument is not a literal or a pinned expression",
    "c2x-environ-subscript-store": (
        "stores into or deletes from os.environ (the body has no subscript store)"
    ),
    "c2x-path-method-write": "calls Path().open outside the allow-list",
    "k8-mode-step-continue-on-error": (
        "job select step 'Selection mode' keys ['continue-on-error', 'env', 'id', 'name', 'run'],"
        " expected ['env', 'id', 'name', 'run']"
    ),
    "k8-mode-step-timeout": (
        "job select step 'Selection mode' keys ['env', 'id', 'name', 'run', 'timeout-minutes'],"
        " expected ['env', 'id', 'name', 'run']"
    ),
    "k8-mode-step-if-pr-data": (
        "job select step 'Selection mode' keys ['env', 'id', 'if', 'name', 'run'], expected ['env',"
        " 'id', 'name', 'run']"
    ),
    "k8-select-job-uses-reusable": (
        "job select keys ['env', 'name', 'outputs', 'runs-on', 'steps', 'timeout-minutes', 'uses'],"
        " expected ['env', 'name', 'outputs', 'runs-on', 'steps', 'timeout-minutes']"
    ),
    "k8-container-credentials": "job select sets container",
    "k8-services-gate": "job ci-gate sets services",
    "k8-checkout-with-ref": (
        "job select step None with {'fetch-depth': '0', 'ref': 'x', 'persist-credentials': 'false'}, expected "
        "{'fetch-depth': '0', 'persist-credentials': 'false'}"
    ),
    "k8-checkout-with-persist": (
        "job select step None with {'fetch-depth': '0', 'persist-credentials': 'true'}, expected"
        " {'fetch-depth': '0', 'persist-credentials': 'false'}"
    ),
}

WF_FORM_GREEN = {
    "c1-quoted-with-only-control": "control: a quoted key with no added key",
    "c2-baseline-unmutated": "control: the unmutated workflow",
    "c2-concurrency-removed": "the concurrency block carries no trust",
    "f2-reorder-select-job-keys": "job keys are an order-insensitive set",
    "f2-reorder-gate-job-keys": "job keys are an order-insensitive set",
    "f2-reorder-wf-env": "workflow env is an order-insensitive mapping",
    "f2-reorder-mat-env": "step env is an order-insensitive mapping",
    "k8-build-index-coe-false": "continue-on-error false moves toward fail closed",
}

WF_FORM_TESTS = {
    "k8-build-index-if-pr-data": (
        ("__self__", "WorkflowShape.test_build_and_select_run_from_the_base_copy"),
    ),
    "k8-select-output-literal": (
        ("__self__", "WorkflowShape.test_select_outputs_fall_back_to_the_full_matrix_step"),
    ),
    "k8-gate-materialise-if-false": (
        ("__self__", "BranchTipGate.test_a_live_base_event_never_runs_the_branch_tip_fold"),
    ),
    "k8-base-fold-if-false": (
        ("__self__", "WorkflowShape.test_gate_job_runs_the_base_gate_when_available"),
    ),
    "k8-gate-timeout-value": (
        (
            "__self__",
            "TrustDecisionFirst.test_code_r13_f2_both_jobs_timeout_minutes_are_pinned",
        ),
    ),
    "w1-ci-comment-reverted": (
        (
            "__self__",
            "TrustDecisionFirst.test_f1_no_post_derivation_report_wording_in_the_workflow_or_this_module",
        ),
    ),
    "k8-gate-job-if-false": (("test_ci_select_gating_8240", "CiGateNeeds.test_gate_runs_always"),),
    "k8-gate-job-if-success": (
        ("test_ci_select_gating_8240", "CiGateNeeds.test_gate_runs_always"),
    ),
    "k8-gate-needs-drop-check": (
        (
            "test_ci_select_gating_8240",
            "CiGateNeeds.test_gate_needs_every_other_job_except_the_b4_set",
        ),
    ),
}

WF_FORM_DOC = "w1-docstring-reverted"
WF_FORM_SAME_AS = {
    "f2-select-mat-env-value": ("F2_MUTANTS", "select step env value"),
    "f2-gate-fold-env-value": ("F2_MUTANTS", "gate fold env value"),
    "f2-select-job-env-value": ("F2_MUTANTS", "select job env value"),
    "f2-select-jobkey-continue-on-error": ("F2_MUTANTS", "select job-level key"),
    "f2-gate-jobkey-concurrency": ("F2_MUTANTS", "gate job-level key"),
    "f2-select-runs-on-self-hosted": ("F2_MUTANTS", "select runs-on self-hosted"),
    "c2-runs-on-self-hosted-select": ("F2_MUTANTS", "select runs-on self-hosted"),
    "f2-gate-runs-on-self-hosted": ("F2_MUTANTS", "gate runs-on self-hosted"),
    "f2-select-perm-contents-write": ("F2_MUTANTS", "select job permissions widened"),
    "f2-gate-perm-write-all": ("F2_MUTANTS", "gate job permissions widened"),
    "f2-wf-perm-contents-write": ("WORKFLOW_PERMISSIONS", "test_f2_workflow_permissions"),
    "c2-sh-getoutput": ("C2_MUTANTS", "sh-getoutput"),
    "c2-sh-posix-spawnp": ("C2_MUTANTS", "sh-posix-spawnp"),
    "c2-sh-call-bare-file": ("C2_MUTANTS", "sh-call-bare-file"),
    "c2-sh-git-alias": ("C2_MUTANTS", "sh-git-alias"),
    "c2-sh-git-fsmonitor": ("C2_MUTANTS", "sh-git-fsmonitor"),
    "c2-second-subprocess-run": ("C2_MUTANTS", "sh-second-run"),
    "c2x-environ-subscript-store": ("C12_MUTANTS", "x-environ-store"),
}


def _apply_form(edits, live):
    text = live
    for edit in edits:
        if callable(edit):
            text = edit(text)
    return text


def _form_pins(edits, text):
    """The re-pinned Materialise digests of a REHASH form (empty for the others)."""
    if "REHASH" not in edits:
        return {}
    doc = yaml_subset_load(text)
    pins = {}
    for job, name in ((SELECT_JOB, MATERIALISE_STEP), (GATE_JOB, GATE_MATERIALISE_STEP)):
        for step in doc["jobs"][job]["steps"]:
            if step.get("name") == name:
                pins[name] = run_digest(step["run"])
    return pins


def docstring_phrase_hits(source, phrase):
    """Names of the docstrings of `source` that hold `phrase` (whitespace folded)."""
    hits = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef)):
            if phrase in " ".join((ast.get_docstring(node) or "").split()):
                hits.append(getattr(node, "name", "module"))
    return hits


def failing_tests_on_workflow(text, specs):
    """Names of the (module, Class.test) specs that fail when CI_YML is `text`."""
    failed = []
    with tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR")) as scratch:
        path = Path(scratch) / "ci.yml"
        path.write_text(text)
        for module_name, dotted in specs:
            module = (sys.modules[__name__] if module_name == "__self__"
                      else importlib.import_module(module_name))
            with unittest.mock.patch.object(module, "CI_YML", path):
                result = unittest.TestResult()
                unittest.defaultTestLoader.loadTestsFromName(dotted, module).run(result)
            if result.errors:
                raise RuntimeError("harness defect: %s errored, which is not a refusal" % dotted)
            if result.failures:
                failed.append(dotted)
    return failed


class WorkflowFormMutants(unittest.TestCase):
    """code r12 C3: every workflow-level form of the round-10 security harness is a row."""

    FORMS = _workflow_forms()

    def test_the_table_carries_all_180_forms_once(self):
        kinds = [set(WF_FORM_RED), set(WF_FORM_TESTS), set(WF_FORM_GREEN), {WF_FORM_DOC}]
        self.assertEqual(sum(len(k) for k in kinds), 180)
        self.assertEqual(set().union(*kinds), set(self.FORMS))
        self.assertEqual((len(WF_FORM_RED), len(WF_FORM_TESTS), len(WF_FORM_GREEN)), (162, 9, 8))
        self.assertTrue(set(WF_FORM_SAME_AS) <= set(WF_FORM_RED))
        self.assertEqual(len(WF_FORM_SAME_AS), 18)

    def test_each_red_form_is_refused_by_the_pre_trust_gate_with_its_problem_line(self):
        live = CI_YML.read_text()
        for fid, needle in WF_FORM_RED.items():
            with self.subTest(form=fid):
                edits = self.FORMS[fid]
                text = _apply_form(edits, live)
                self.assertNotEqual(text, live)
                with unittest.mock.patch.dict(MATERIALISE_SHA256, _form_pins(edits, text)):
                    problems = pre_trust_problems(text)
                self.assertTrue([p for p in problems if needle in p], (needle, problems[:3]))

    def test_each_rehash_form_is_refused_with_the_pin_matching_the_mutated_text(self):
        """With the pin re-pinned the sha256 check is quiet, so the second layer is what refuses."""
        live = CI_YML.read_text()
        rehashed = [fid for fid in WF_FORM_RED if "REHASH" in self.FORMS[fid]]
        self.assertTrue(rehashed)
        for fid in rehashed:
            with self.subTest(form=fid):
                edits = self.FORMS[fid]
                text = _apply_form(edits, live)
                with unittest.mock.patch.dict(MATERIALISE_SHA256, _form_pins(edits, text)):
                    problems = pre_trust_problems(text)
                self.assertFalse([p for p in problems if "sha256" in p], problems)

    def test_each_form_another_test_refuses_fails_those_tests_on_the_mutated_text(self):
        live = CI_YML.read_text()
        self.assertEqual(failing_tests_on_workflow(live, [
            spec for specs in WF_FORM_TESTS.values() for spec in specs]), [])
        for fid, specs in WF_FORM_TESTS.items():
            with self.subTest(form=fid):
                text = _apply_form(self.FORMS[fid], live)
                self.assertNotEqual(text, live)
                self.assertTrue(failing_tests_on_workflow(text, specs))

    def test_a_planted_erroring_test_is_a_harness_defect_not_a_refusal(self):
        """code r13 F2: a spec that errors is reported as a harness defect; only a failing spec
        counts as a refusal."""
        planted = type("Planted", (unittest.TestCase,), {
            "test_fails": lambda self: self.fail("refused"),
            "test_errors": lambda self: 1 // 0,
            "test_passes": lambda self: None,
        })
        fake = types.ModuleType("planted_8240")
        fake.Planted = planted
        fake.CI_YML = None
        with unittest.mock.patch.dict(sys.modules, {"planted_8240": fake}):
            self.assertEqual(failing_tests_on_workflow("x: 1\n", [
                ("planted_8240", "Planted.test_fails"), ("planted_8240", "Planted.test_passes")]),
                ["Planted.test_fails"])
            with self.assertRaisesRegex(RuntimeError, "harness defect"):
                failing_tests_on_workflow("x: 1\n", [("planted_8240", "Planted.test_errors")])

    def test_sec_r13_s2_no_other_job_carries_the_gate_check_name(self):
        """sec r13 S2, sec r14 S2, code r14 F1: the check context named by the gate stays unique
        (case, padding and the job id of a nameless job folded), no job name holds an expression
        outside the two pinned matrix names, and the select job's display name is pinned."""
        live = CI_YML.read_text()
        for label, old, new, needle in (
                ("classify-named-ci-gate", "    name: Classify changes\n", "    name: ci-gate\n",
                 "carries the gate check name"),
                ("select-named-ci-gate", "    name: Impact selection\n", "    name: ci-gate\n",
                 "carries the gate check name"),
                ("select-name-changed", "    name: Impact selection\n",
                 "    name: Impact selection x\n", "job select name"),
                ("classify-named-CI-GATE", "    name: Classify changes\n", "    name: CI-GATE\n",
                 "carries the gate check name"),
                ("classify-named-Ci-Gate", "    name: Classify changes\n", "    name: Ci-Gate\n",
                 "carries the gate check name"),
                ("classify-named-trailing-space", "    name: Classify changes\n",
                 '    name: "ci-gate "\n', "carries the gate check name"),
                ("classify-named-leading-space", "    name: Classify changes\n",
                 '    name: " ci-gate"\n', "carries the gate check name"),
                ("classify-named-by-expression", "    name: Classify changes\n",
                 "    name: ${{ 'ci-gate' }}\n", "name carries an expression"),
                ("classify-named-by-format", "    name: Classify changes\n",
                 "    name: ${{ format('ci-{0}', 'gate') }}\n", "name carries an expression"),
                ("lint-name-any-expression", "    name: Lint (fmt + clippy)\n",
                 "    name: Lint ${{ github.sha }}\n", "name carries an expression"),
                ("check-name-other-matrix-expression", "    name: Check (${{ matrix.leg }})\n",
                 "    name: Check (${{ matrix.other }})\n", "name carries an expression"),
                ("classify-id-is-gate-no-name", "  classify:\n    name: Classify changes\n",
                 "  CI-GATE:\n", "defaults its check name"),
                ("classify-id-is-gate-padded-no-name", "  classify:\n    name: Classify changes\n",
                 '  "ci-gate ":\n', "defaults its check name"),
                ("classify-name-is-a-list", "    name: Classify changes\n", "    name: [ci-gate]\n",
                 "name is not a string"),
                ("classify-name-is-a-mapping", "    name: Classify changes\n",
                 "    name:\n      x: y\n", "name is not a string")):
            with self.subTest(form=label):
                text = live.replace(old, new, 1)
                self.assertNotEqual(text, live)
                problems = pre_trust_problems(text)
                self.assertTrue([p for p in problems if needle in p], (needle, problems))
        self.assertEqual(pre_trust_problems(live), [])
        jobs = yaml_subset_load(live)["jobs"]
        names = [d["name"] for d in jobs.values() if "name" in d]
        self.assertEqual((len(jobs), len(names)), (13, 13))
        self.assertEqual({n for n in names if "${{" in n}, JOB_NAME_EXPRESSIONS)
        self.assertEqual(_fold_name("  CI-\tGate "), "ci- gate")

    R18_PINNED = (
        ("check", "Check (${{ matrix.leg }})", "leg"),
        ("mobile-cross-compile", "Cross-compile (${{ matrix.target }})", "target"),
    )

    def test_sec_r15_a_matrix_names_are_bound_to_their_job_and_matrix_key(self):
        """sec r15 A: each pinned matrix display name is accepted on its own job id and only
        while that job carries a strategy.matrix holding the referenced key; the value on any
        other job, or on its own job without the key, is a problem line."""
        live = CI_YML.read_text()
        jobs = yaml_subset_load(live)["jobs"]
        self.assertEqual(JOB_MATRIX_NAMES, {job: (name, key) for job, name, key in self.R18_PINNED})
        for job, name, key in self.R18_PINNED:
            other_name = next(p[1] for p in self.R18_PINNED if p[0] != job)
            host_line = "    name: %s\n" % name
            rows = [
                ("%s-name-on-classify-no-matrix" % job, "    name: Classify changes\n",
                 host_line),
                ("%s-name-on-lint-no-matrix" % job, "    name: Lint (fmt + clippy)\n", host_line),
                ("%s-name-on-the-other-pinned-job" % job, "    name: %s\n" % other_name,
                 host_line),
            ]
            for label, old, new in rows:
                with self.subTest(form=label):
                    text = live.replace(old, new, 1)
                    self.assertNotEqual(text, live)
                    problems = pre_trust_problems(text)
                    self.assertTrue([p for p in problems if "name carries an expression" in p],
                                    problems)
            self.assertEqual(_job_name_problems(job, jobs[job]), [])

            def rename_key(definition, key=key):
                for entry in definition["strategy"]["matrix"]["include"]:
                    entry[key + "x"] = entry.pop(key)

            def rename_one_entry(definition, key=key):
                entry = definition["strategy"]["matrix"]["include"][0]
                entry[key + "x"] = entry.pop(key)

            def drop_matrix(definition):
                del definition["strategy"]["matrix"]

            def drop_strategy(definition):
                del definition["strategy"]

            def string_matrix(definition):
                definition["strategy"]["matrix"] = "${{ fromJSON(needs.x.outputs.m) }}"

            def empty_include(definition):
                definition["strategy"]["matrix"] = {"include": []}

            for label, mutate in (("matrix-key-renamed", rename_key),
                                  ("one-include-entry-lacks-the-key", rename_one_entry),
                                  ("matrix-absent", drop_matrix),
                                  ("strategy-absent", drop_strategy),
                                  ("matrix-is-a-string", string_matrix),
                                  ("matrix-include-empty", empty_include)):
                with self.subTest(form="%s-%s" % (job, label)):
                    definition = copy.deepcopy(jobs[job])
                    mutate(definition)
                    problems = _job_name_problems(job, definition)
                    self.assertTrue([p for p in problems if "matrix" in p], problems)
        for third in ("ci", "x-check", "mobile", "Check", "check ", "CHECK"):
            for _, name, _ in self.R18_PINNED:
                with self.subTest(form="third-job-%r-%s" % (third, name[:5])):
                    definition = {"name": name, "runs-on": "ubuntu-latest",
                                  "strategy": {"matrix": {"leg": ["a"], "target": ["b"]}}}
                    problems = _job_name_problems(third, definition)
                    self.assertTrue([p for p in problems if "name carries an expression" in p],
                                    problems)

    def test_sec_r15_b_null_and_empty_job_names_are_refused_and_the_id_is_judged(self):
        """sec r15 B: a job name that is the YAML null spelling or empty (or only whitespace) is a
        problem line naming the job, and the job is still judged by its folded id."""
        live = CI_YML.read_text()
        hosts = (("classify", "  classify:\n    name: Classify changes\n"),
                 ("lint", "  lint:\n    name: Lint (fmt + clippy)\n"))
        spellings = ("null", "~", "Null", "NULL", '""', "''", '" "', '"\\t"', '"  "')
        ids = ("CI-GATE", "Ci-Gate", '"ci-gate "', "ci_gate", "plain")
        for host, header in hosts:
            for ident in ids:
                for spelling in spellings:
                    label = "%s-id-%s-name-%s" % (host, ident, spelling)
                    with self.subTest(form=label):
                        text = live.replace(
                            header, "  %s:\n    name: %s\n" % (ident, spelling), 1)
                        self.assertNotEqual(text, live)
                        problems = pre_trust_problems(text)
                        shown = ident.strip('"')
                        self.assertTrue(
                            [p for p in problems if "null or empty name" in p and shown in p],
                            problems)
                        by_id = [p for p in problems if "defaults its check name" in p]
                        if ident in ("CI-GATE", "Ci-Gate", '"ci-gate "'):
                            self.assertTrue(by_id, problems)
                        else:
                            self.assertFalse(by_id, problems)
        with self.subTest(form="bare-empty-name"):
            text = live.replace(hosts[0][1], "  classify:\n    name:\n", 1)
            problems = pre_trust_problems(text)
            self.assertTrue([p for p in problems if "null or empty name" in p], problems)
        with self.subTest(form="gate-job-null-name"):
            text = live.replace("    name: ci-gate\n", "    name: null\n", 1)
            problems = pre_trust_problems(text)
            self.assertTrue([p for p in problems if "null or empty name" in p], problems)
        for fine in ("nullable", "null job", "Nul", "~x"):
            with self.subTest(form="not-a-null-spelling-%s" % fine):
                self.assertEqual(_job_name_problems("classify", {"name": fine}), [])

    def test_each_form_that_stays_green_stays_green(self):
        live = CI_YML.read_text()
        for fid, reason in WF_FORM_GREEN.items():
            with self.subTest(form=fid):
                self.assertTrue(reason)
                self.assertEqual(pre_trust_problems(_apply_form(self.FORMS[fid], live)), [])

    def test_the_docstring_form_reverts_a_docstring_to_the_banned_wording(self):
        source = Path(__file__).read_text()
        phrase = TrustDecisionFirst.BANNED_PHRASE
        old = "    derivation is inline with no resolver script run over keeping a resolver\n"
        self.assertEqual(self.FORMS[WF_FORM_DOC], ["DOCSTRING_REVERT"])
        self.assertEqual(source.count(old), 2)
        self.assertEqual(docstring_phrase_hits(source, phrase), [])
        reverted = source.replace(
            old, "    resolver is demoted to a post-" + "derivation report over keeping it\n", 1)
        self.assertTrue(docstring_phrase_hits(reverted, phrase))

    def test_the_eighteen_mapped_forms_equal_the_text_of_the_existing_row(self):
        live = CI_YML.read_text()
        for fid, (table, label) in WF_FORM_SAME_AS.items():
            with self.subTest(form=fid, row=label):
                if table == "F2_MUTANTS":
                    row = next(r for r in TrustDecisionFirst.F2_MUTANTS if r[0] == label)
                    existing = TrustDecisionFirst.mutated(None, row[1], row[2], row[3])
                elif table == "WORKFLOW_PERMISSIONS":
                    existing = live.replace("\npermissions:\n  contents: read\n",
                                            "\npermissions:\n  contents: write\n")
                else:
                    line = next(r[1] for r in getattr(TrustDecisionFirst, table) if r[0] == label)
                    anchor = TrustDecisionFirst.C2_MUTANT_ANCHOR
                    existing = live.replace(
                        anchor, anchor + "          " + line.replace("\n", "\n          ") + "\n")
                self.assertEqual(_apply_form(self.FORMS[fid], live), existing)


if __name__ == "__main__":
    unittest.main()
