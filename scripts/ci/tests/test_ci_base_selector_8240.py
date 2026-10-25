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
import hashlib
import io
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
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
    (None, {"uses", "with"}, set(), {"fetch-depth": "0"}, None),
    ("Selection mode", {"name", "id", "env", "run"}, {"ENFORCE"}, None, ECHO_RUN),
    (MATERIALISE_STEP, {"name", "id", "env", "run"}, MATERIALISE_ENV, None, HEREDOC),
    ("Build impact index", {"name", "if", "continue-on-error", "run"}, set(), None, INDEX_RUN),
)
GATE_ALLOW = (
    (None, {"uses", "with"}, set(), {"fetch-depth": "0"}, None),
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
# sec F1 / code C1-C3 (round 12), sec r10 S1-S4 (round 13) and code r10 C1-C4 (round 13): the
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
# MATERIALISE_GIT_VALUE_ARGS.
# names resolved by binding: each name in a pinned git expression, in an open() or Path() argument
# and the root name of every method call has exactly one binding in its function, and that
# binding is the enumerated one in MATERIALISE_VALUE_BINDINGS (an unrebound parameter, a single
# pinned assignment, a single pinned for loop, or only `with open(...)` for handle); IMPACT_PREFIX
# and SHA_RE have exactly one module-level binding to their constant in
# MATERIALISE_CONST_BINDINGS. Any other binding is a problem line.
# environment untouched, read-only environment uses: every name bound from os.environ (a dict
# copy, an alias, the `env` keyword of subprocess.run, a parameter that receives it) and
# os.environ itself may only be read through a subscript load, .get, .items, .keys, .values, `in`,
# a dict() copy or the env keyword; every other reference, store, delete, update, pop, clear or
# pass-on is a problem line, and the body has no subscript store.
# open() takes only the enumerated MATERIALISE_OPEN_ARGS with mode "a", Path() only
# MATERIALISE_PATH_ARGS, and the `__main__` guard is the last top-level statement and holds
# exactly `sys.exit(main())`.
# The layer does not check runtime values (environment variable contents, the IMPACT_FILES names,
# fetched blob bytes) or what the allowed local functions do beyond the rules above. The sha256
# digest stays the primary pin.
MATERIALISE_ENFORCES = ("call targets", "pinned imports", "no rebinding", "exact argv head",
                        "dash literals", "environment untouched",
                        "unrebound parameter", "exactly one binding",
                        "read-only environment uses")
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
    ("derive_base", "env"): "param",
    ("fetch_blob", "base"): "param",
    ("fetch_blob", "name"): "param",
    ("fetch_blob", "path"): "IMPACT_PREFIX + name",
    ("fetch_blob", "tree"): "git('ls-tree', base, '--', path)",
    ("gate_absent", "base"): "param",
    ("gate_absent", "tree"): "git('ls-tree', base, '--', IMPACT_PREFIX + 'gate.py')",
    ("git_state_refused", "rel"): "for:('info/grafts', 'shallow', 'objects/info/alternates')",
    ("git_state_refused", "res"): "git('rev-parse', '--git-path', rel)",
    ("have_commit", "base"): "param",
    ("materialise", "base"): "param",
    ("materialise", "dest"): "param",
    ("materialise", "name"): "for:names",
    ("materialise", "names"): "param",
    ("materialise", "target"): "dest / 'impact' / name",
    ("replace_refs_present", "listed"): "git('replace', '--list')",
    ("replace_refs_present", "res"):
        "git('for-each-ref', '--count=1', '--format=%(refname)', 'refs/replace/')",
    ("report", "handle"): "with-open",
    ("report", "summary"): "os.environ.get('GITHUB_STEP_SUMMARY')",
    ("rev_parse", "res"): "git('rev-parse', '--verify', '--quiet', spec)",
    ("rev_parse", "spec"): "param",
}
# Module-level names: exactly one binding in the whole body, an assignment of this value.
MATERIALISE_CONST_BINDINGS = {"IMPACT_PREFIX": "'scripts/ci/impact/'",
                              "SHA_RE": "re.compile('^[0-9a-f]{40}$')"}
# Module chains read as a VALUE rather than called: the environment (checked by the read-only rule)
# and the one exception class, which is accepted only as an `except` type.
MATERIALISE_VALUE_CHAINS = {"os.environ", "subprocess.TimeoutExpired"}
MATERIALISE_ENV_PARAMS = {"env"}  # parameters that receive os.environ (derive_base)
MATERIALISE_ENV_READS = {"get", "items", "keys", "values"}
MATERIALISE_ENV_COPIERS = {"dict", "derive_base"}  # callees that may take an environment mapping
MATERIALISE_OPEN_ARGS = sorted(["os.environ['GITHUB_OUTPUT']", "summary"])
MATERIALISE_PATH_ARGS = sorted(["os.environ['RUNNER_TEMP']"])
MATERIALISE_GUARD_TEST = "__name__ == '__main__'"
MATERIALISE_GUARD_BODY = ["sys.exit(main())"]


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
    return len(local) == 1 and local[0][1] == "arg" and any(local[0][2] is p for p in params)


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
        return [] if _param_ok(scope, name) else ["%s is not an unrebound parameter" % name]
    local = _local_bindings(scope, name)
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


def _env_use_ok(node, parents):
    """True when the reference is one of the read-only uses of an environment mapping."""
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
        return node in parent.args and isinstance(parent.func, ast.Name) \
            and parent.func.id in MATERIALISE_ENV_COPIERS
    if isinstance(parent, ast.Assign):
        return parent.value is node  # an alias or copy: the target is itself checked
    return False


def _environment_problems(label, tree, parents):
    """Positive rule: an environment mapping is only read (subscript load, .get/.items/.keys/
    .values, `in`, a dict() copy, the env keyword); every other reference is a problem line."""
    names = _environment_names(tree)
    problems = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id in names:
            if isinstance(node.ctx, ast.Load):
                ok = _env_use_ok(node, parents)
            else:
                parent = parents.get(node)
                ok = (isinstance(node.ctx, ast.Store) and isinstance(parent, ast.Assign)
                      and node in parent.targets)
            if not ok:
                problems.append("%s: environment mapping %s used outside the read-only forms"
                                % (label, node.id))
        elif isinstance(node, ast.Attribute) and _chain(node) == "os.environ":
            if not _env_use_ok(node, parents):
                problems.append("%s: environment mapping os.environ used outside the read-only "
                                "forms" % label)
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
    parents = _parents(tree)
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
    for job in (SELECT_JOB, GATE_JOB):
        allow, marker = WINDOWS[job]
        definition = _mapping(jobs.get(job), "job %s" % job, problems)
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
                       "does not check"):
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
    CHECKOUT_WITH = "        with:\n          fetch-depth: 0\n"

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
            self.assertEqual(len(problems), 1)
            self.assertIn(name, problems[0])
            self.assertIn(run_digest(changed), problems[0])
            self.assertIn(MATERIALISE_SHA256[name], problems[0])
            self.assertNotIn("GIT_TIMEOUT_S", problems[0])

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


if __name__ == "__main__":
    unittest.main()
