"""Workflow-command injection from pull-request bytes into the runner log of ci.yml (#9433, #9434).

Invariant: no byte a pull request controls (a changed file name, a classifier reason derived from one, a line a
PR-run test or the PR-tree selector writes to a log) reaches the runner log in a position where the runner reads it
as a workflow command (``::name::`` at a line start, ``##[`` anywhere), in any locale, on any runner image.

Every cell takes the REAL step text from .github/workflows/ci.yml (parsed YAML, step found by job and id or name,
span cut at fixed anchor lines) and executes it with ``bash --noprofile --norc -eo pipefail`` (the ``shell: bash``
of GitHub Actions) against stub inputs. Expected values are computed in Python; no host text tool is used for them.

* #9434 ``classify``/``cls``: the cargo_skip notice. The reason goes through scripts/ci/workflow_annotation.py
  taken from the TRUSTED (merge-base) tree, never from the workspace; when no trusted copy runs, a fixed notice.
* #9433 ``check``/``Run tests (impact-aware)``: each shard log is printed between ``::stop-commands::<token>`` and
  ``::<token>::``; the token is 32 lowercase hex from the CSPRNG, new per block and per run, never shown earlier.
  Without a token the log is not printed (a fixed notice) and the exit code stays the base behaviour.
* Siblings of the class in ci.yml: the changed-file list of ``cls`` (same stop-commands block), the PR-tree
  selector log of ``impact`` (first 200 lines, ``::`` and ``##[`` spaced as the sed it replaces spaced ``::``), and the enterprise-fed database name, which is cut in BYTES by Python (uutils
  ``cut -c`` cuts characters, GNU ``cut -c`` cuts bytes).
"""

import importlib.util
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[3]
WORKFLOW = REPO / ".github" / "workflows" / "ci.yml"
ANNOTATION_MODULE = REPO / "scripts" / "ci" / "workflow_annotation.py"
SCRATCH_PARENT = REPO / ".local-runs"
BASH = shutil.which("bash") or "/bin/bash"
GIT = shutil.which("git") or "/usr/bin/git"
BASH_SHELL = (BASH, "--noprofile", "--norc", "-eo", "pipefail", "-c")
HOST_BIN_DIRS = ("/usr/local/bin", "/usr/bin", "/bin")
RUN_TIMEOUT_SECS = 120
LARGE_VALUE_BYTES = 100_000
LARGE_VALUE_CEILING_SECS = 20.0
MIB = 1 << 20
TOKEN_RE = re.compile(rb"[0-9a-f]{32}")
TOKEN_HEX_CHARS = 32
LOCALES = ("C", "C.UTF-8")
SHARDS = ("serial", "parallel_1", "parallel_2")
STOP_PREFIX = b"::stop-commands::"
GUESSED_HEX_TOKEN = b"0123456789abcdef0123456789abcdef"
FED_DB_MAX_BYTES = 59
AFTER_MARK = "AFTER-BLOCK-9433"

# step anchors (job, key, kind) and span anchors (start predicate, end predicate, inclusive flags)
CLS = ("classify", "cls")
IMPACT = ("classify", "impact")
TESTS = ("check", "Run tests (impact-aware)")
FED = ("check", "Configure enterprise-fed tier (per-job ephemeral db, enterprise-fed legs only)")

NOTICE_TRUE_TEMPLATE = "cargo_skip=true ({reason}) - cargo legs no-op"
NOTICE_FALSE_TEMPLATE = "cargo_skip=false ({reason}) - running full pipeline"
NOTICE_FALLBACK = {
    "true": b"::notice::cargo_skip=true (reason not shown: the trusted escaper did not run) - cargo legs no-op\n",
    "false": b"::notice::cargo_skip=false (reason not shown: the trusted escaper did not run) - running full pipeline\n",
}
SHARD_FALLBACK = ("::notice::[#9433] %s shard output not printed: no stop-commands token could be made "
                  "(fail closed; the step result is unchanged)\n")
CHANGED_FALLBACK = (b"::notice::[#9433] changed-file list not printed: no stop-commands token could be made "
                    b"(fail closed; the classification is unchanged)\n")
IMPACT_LINES = 200

REASON_CORPUS = {
    "v2_command": b"rust-observable-path ::error::x cargo_skip-rules-v3",
    "percent_lf": b"rust-observable-path src/%0A::error::x cargo_skip-rules-v3",
    "newline": b"rust-observable-path src/a\n::error::x cargo_skip-rules-v3",
    "carriage_return": b"rust-observable-path src/a\r::error::x cargo_skip-rules-v3",
    "lone_percent": b"rust-observable-path src/100%.rs cargo_skip-rules-v3",
    "v1_command": b"rust-observable-path src/##[error]x.rs cargo_skip-rules-v3",
    "non_utf8": b"rust-observable-path src/\xff\xfe::error::x cargo_skip-rules-v3",
    "hash_boundary": b"C# ##[group]x #",
}

LOG_CORPUS = {
    "v2_error": b"::error::x\n",
    "add_mask": b"::add-mask::x\n",
    "stop_guess": b"::stop-commands::guess\n::error::after-guess\n",
    "end_empty": b"::::\n::error::after-empty-end\n",
    "end_pause": b"::pause::\n::error::after-pause\n",
    "end_hex_literal": b"::" + GUESSED_HEX_TOKEN + b"::\n::error::after-hex\n",
    "v1_group": b"##[group]x\nmid line ##[error]y\n",
    "cr_only": b"ok\r::error::a\r::warning::b\r",
    "no_final_newline": b"line one\n::error::tail",
    "mib_line": b"A" * MIB + b"::error::x\n",
    "mib_no_newline_at_all": b"A" * MIB + b"::error::x##[group]y",
    "crlf": b"ok\r\n::error::a\r\n##[group]b\r\n",
    "non_utf8": b"\xff\xfe::error::x\n",
    "empty": b"",
}
MIB_CEILING_SECS = 20.0

# #9433 (ruling (a) 2): the impact print at the base a028c45e was this one line between the span anchors.
BASE_SHA = "a028c45e55c7817b88c4b139347f407387e4a02c"
BASE_IMPACT_SPAN = "sed -n '1,200{s/::/: :/g;p}' \"$impact_log\"\n"
# (base rc, head rc) of the impact print, measured with GNU sed 4.9 at the base. "unreadable" differs:
# sed exits 2, the head print exits 1; the conductor rules which one is right (needs-conductor in READY).
# Until then the measured pair is pinned so any change of either is red.
IMPACT_RC_TABLE = {"readable": (0, 0), "missing": (2, 2), "unreadable": (2, 1)}
IMPACT_RC_PENDING_RULING = frozenset({"unreadable"})
TRUST_DIR_MODE = 0o700
TRUST_FILES = {"__init__.py": b"", "common.py": b"# trusted common 9434\n",
               "cargo_skip.py": b"# trusted decider 9434\n", "rules.json": b"{}\n"}
PARTIAL_PRINT = b"partial-print-no-newline::error::x"

CHANGED_CORPUS = {
    "v2_name": "src/a.rs\n::error::x\nsrc/b.rs",
    "v1_name": "docs/##[error]x.md",
    "stop_name": "::stop-commands::guess\n::error::y",
    "hex_end": "::%s::\n::error::z" % GUESSED_HEX_TOKEN.decode(),
}


def load_workflow_annotation():
    spec = importlib.util.spec_from_file_location("workflow_annotation_9433", ANNOTATION_MODULE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def step_run(job, key, workflow_text=None):
    workflow = yaml.safe_load(workflow_text if workflow_text is not None else WORKFLOW.read_text(encoding="utf-8"))
    for step in workflow["jobs"][job]["steps"]:
        if step.get("id") == key or step.get("name") == key:
            return step["run"]
    raise AssertionError("step %s/%s not found in ci.yml" % (job, key))


def span(run, start, end, start_inclusive=True, end_inclusive=False):
    """The lines of ``run`` from the first line matching ``start`` to the next matching ``end``."""
    lines = run.split("\n")
    first = next((i for i, line in enumerate(lines) if start(line)), None)
    if first is None:
        raise AssertionError("span start anchor missing")
    last = next((i for i in range(first + 1, len(lines)) if end(lines[i])), None)
    if last is None:
        raise AssertionError("span end anchor missing")
    return "\n".join(lines[first if start_inclusive else first + 1:last + 1 if end_inclusive else last]) + "\n"


def notice_span():
    run = step_run(*CLS)
    lines = run.split("\n")
    case = next(i for i, line in enumerate(lines) if line.strip() == 'case "$docs_only$cargo_skip" in')
    esac = next(i for i in range(case, len(lines)) if lines[i].strip() == "esac")
    header = next(i for i in range(esac, len(lines)) if lines[i].strip().startswith('echo "--- Changed files'))
    return "\n".join(lines[esac + 1:header]) + "\n"


def changed_span():
    return span(step_run(*CLS), lambda l: l.strip().startswith('echo "--- Changed files'),
                lambda l: l.strip().startswith("# #8328 round 3 (REVIEW-8328-code-r2"))


def impact_span(workflow_text=None):
    return span(step_run(*IMPACT, workflow_text=workflow_text),
                lambda l: 'scripts/ci-test-impact.sh "$IMPACT_BASE"' in l,
                lambda l: l.strip().startswith("# Allow-list: four keys"), start_inclusive=False)


def trust_setup_span():
    """The cls trust-directory setup: from ``trust_dir=`` to the ``skip_out=`` line."""
    return span(step_run(*CLS), lambda l: l.strip().startswith("trust_dir="),
                lambda l: l.strip().startswith("skip_out="))


def base_workflow_text():
    """ci.yml at the base a028c45e when the object is in the clone, else None (a shallow clone)."""
    probe = subprocess.run([GIT, "-C", str(REPO), "cat-file", "-e", BASE_SHA + ":.github/workflows/ci.yml"],
                           capture_output=True, timeout=RUN_TIMEOUT_SECS, check=False)
    if probe.returncode != 0:
        return None
    return subprocess.run([GIT, "-C", str(REPO), "show", BASE_SHA + ":.github/workflows/ci.yml"],
                          capture_output=True, text=True, timeout=RUN_TIMEOUT_SECS, check=True).stdout


def shard_span():
    run = step_run(*TESTS)
    lines = run.split("\n")
    first = next(i for i, line in enumerate(lines) if line.strip() == "for n in serial parallel_1 parallel_2; do")
    indent = lines[first][:len(lines[first]) - len(lines[first].lstrip())]
    last = next(i for i in range(first + 1, len(lines)) if lines[i] == indent + "done")
    return "\n".join(lines[first:last + 1]) + "\n"


def fed_span():
    return span(step_run(*FED), lambda l: l.strip().startswith("leg_sanitized="),
                lambda l: l.strip().startswith('echo "CI_FED_DB='), end_inclusive=True)


def runner_commands(out):
    """The workflow commands the runner acts on: v2 ``::`` line start, v1 ``##[`` anywhere, honouring stop-commands.

    Lines split as .NET ReadLine splits them (CR, LF, CRLF). Returns (commands, still_stopped).
    """
    text = out.decode("utf-8", "surrogateescape")
    stop = None
    commands = []
    for line in re.split(r"\r\n|\r|\n", text):
        stripped = line.lstrip()
        if stop is not None:
            if stripped.startswith("::") and stripped[2:].split("::", 1)[0].split(" ", 1)[0] == stop:
                commands.append("<end %s>" % stop)
                stop = None
            continue
        if stripped.startswith("::") or "##[" in line:
            commands.append(line)
            if stripped.startswith("::stop-commands::"):
                stop = stripped[len("::stop-commands::"):]
    return commands, stop is not None


def take_block(test, out, pos, content):
    """Assert a stop-commands block with exactly ``content`` at ``out[pos:]``; return (token, end position)."""
    test.assertTrue(out.startswith(STOP_PREFIX, pos), "no stop-commands line at %d: %r" % (pos, out[pos:pos + 80]))
    token_at = pos + len(STOP_PREFIX)
    token = out[token_at:token_at + TOKEN_HEX_CHARS]
    test.assertRegex(token, TOKEN_RE)
    test.assertEqual(out[token_at + TOKEN_HEX_CHARS:token_at + TOKEN_HEX_CHARS + 1], b"\n")
    test.assertNotIn(token, out[:pos], "token visible before its stop line")
    body = token_at + TOKEN_HEX_CHARS + 1
    shown = content + (b"\n" if content and not content.endswith(b"\n") else b"")
    test.assertEqual(out[body:body + len(shown)], shown, "log bytes changed inside the block")
    end_line = b"::" + token + b"::\n"
    test.assertEqual(out[body + len(shown):body + len(shown) + len(end_line)], end_line, "end marker missing")
    return token, body + len(shown) + len(end_line)


class Sandbox:
    """A scratch directory under the repo's .local-runs (never /tmp), removed behind a path guard."""

    def __init__(self):
        SCRATCH_PARENT.mkdir(exist_ok=True)
        self.root = Path(tempfile.mkdtemp(prefix="notice-9433-", dir=str(SCRATCH_PARENT)))

    def close(self):
        resolved = self.root.resolve()
        if resolved.parent != SCRATCH_PARENT.resolve() or not resolved.name.startswith("notice-9433-"):
            raise AssertionError("refusing to remove %s" % resolved)
        for path in resolved.rglob("*"):
            if not path.is_symlink():
                path.chmod(stat.S_IRWXU)
        shutil.rmtree(resolved)

    def shim_bin(self, name, body):
        """A bin dir with every host tool except python, plus a python3 stand-in (``body`` None = no python3)."""
        bindir = self.root / ("bin-" + name)
        bindir.mkdir()
        for host_dir in HOST_BIN_DIRS:
            for tool in sorted(Path(host_dir).iterdir()) if Path(host_dir).is_dir() else ():
                if tool.name.startswith("python") or (bindir / tool.name).exists():
                    continue
                if tool.is_file() and os.access(tool, os.X_OK):
                    (bindir / tool.name).symlink_to(tool)
        if body is not None:
            shim = bindir / "python3"
            shim.write_text("#!%s -I\nimport sys\n%s\n" % (sys.executable, body), encoding="utf-8")
            shim.chmod(stat.S_IRWXU)
        return str(bindir)


def run_bash(script, cwd, env_extra=None, locale="C.UTF-8", path=None):
    env = {
        b"PATH": os.fsencode(path or os.environ.get("PATH", "/usr/bin:/bin")),
        b"HOME": os.fsencode(str(cwd)),
        b"LC_ALL": locale.encode(),
        b"LANG": locale.encode(),
    }
    for key, value in (env_extra or {}).items():
        env[os.fsencode(key)] = value if isinstance(value, bytes) else os.fsencode(value)
    started = time.monotonic()
    result = subprocess.run([*BASH_SHELL, script], cwd=str(cwd), env=env, capture_output=True,
                            timeout=RUN_TIMEOUT_SECS, check=False)
    return result, time.monotonic() - started


def git(cwd, *args):
    # A throwaway identity with no mail domain: the fixture repo is never pushed.
    subprocess.run([GIT, "-c", "user.name=fixture-9433", "-c", "user.email=fixture-9433", "-c",
                    "commit.gpgsign=false", "-c", "core.hooksPath=" + os.devnull, *args], cwd=str(cwd),
                   check=True, capture_output=True, timeout=RUN_TIMEOUT_SECS)


def make_trusted_repo(root, with_escaper=True, escaper_text=None, name="repo"):
    """A git repo whose base commit holds the escaper (or ``escaper_text``) and the trusted classifier files;
    HEAD replaces the escaper with a hostile workspace copy."""
    repo = root / name
    (repo / "scripts" / "ci" / "impact").mkdir(parents=True)
    git(repo, "init", "-q")
    for trust_file, content in TRUST_FILES.items():
        (repo / "scripts" / "ci" / "impact" / trust_file).write_bytes(content)
    if escaper_text is not None:
        (repo / "scripts" / "ci" / "workflow_annotation.py").write_text(escaper_text, encoding="utf-8")
    elif with_escaper:
        shutil.copyfile(ANNOTATION_MODULE, repo / "scripts" / "ci" / "workflow_annotation.py")
    (repo / "README.md").write_text("base\n", encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "base")
    base = subprocess.run([GIT, "rev-parse", "HEAD"], cwd=str(repo), capture_output=True, text=True,
                          check=True).stdout.strip()
    hostile = ("def annotation(command, message, **kw):\n    return '::error::WORKSPACE-ESCAPER-USED ' + message\n"
               "def render(template, **values):\n    return template.format(**values)\n")
    (repo / "scripts" / "ci" / "workflow_annotation.py").write_text(hostile, encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "head")
    return repo, base


class NoticeEscape9434(unittest.TestCase):
    """#9434: the cargo_skip notice of ``cls`` carries the reason only through the trusted escaper."""

    @classmethod
    def setUpClass(cls):
        cls.wa = load_workflow_annotation()
        cls.box = Sandbox()
        cls.repo, cls.base = make_trusted_repo(cls.box.root)
        cls.span = notice_span()

    @classmethod
    def tearDownClass(cls):
        cls.box.close()

    def run_notice(self, cargo_skip, reason, locale="C.UTF-8", path=None, base=None, repo=None,
                   escaper_path_is_dir=False):
        trust_dir = self.box.root / ("trusted-%d" % time.monotonic_ns())
        (trust_dir / "scripts" / "ci" / "impact").mkdir(parents=True)
        if escaper_path_is_dir:
            # a failed write: the escaper's target in the trust directory cannot be written
            (trust_dir / "scripts" / "ci" / "workflow_annotation.py").mkdir()
        prelude = ('cargo_skip="$STUB_SKIP"; cargo_skip_reason="$STUB_REASON"; trust_dir="$STUB_TRUST_DIR"; '
                   'trust_impact="$trust_dir/scripts/ci/impact"; trust_ref="$STUB_REF"\n')
        return run_bash(prelude + self.span, repo or self.repo, locale=locale, path=path, env_extra={
            "STUB_SKIP": cargo_skip, "STUB_REASON": reason, "STUB_TRUST_DIR": str(trust_dir),
            "STUB_REF": base or self.base})

    def test_escaper_show_write_load_failures_never_use_the_workspace_copy(self):
        """Ruling (a) 1: a failed git show, a failed write, a failed load: the fixed notice, never the
        workspace copy (which, in every form, is the hostile WORKSPACE-ESCAPER-USED module)."""
        box = Sandbox()
        try:
            no_escaper, no_escaper_base = make_trusted_repo(box.root, with_escaper=False, name="show")
            broken, broken_base = make_trusted_repo(box.root, escaper_text="def annotation(:\n", name="load")
            forms = {
                "show_fails": dict(repo=no_escaper, base=no_escaper_base),
                "write_fails": dict(escaper_path_is_dir=True),
                "load_fails": dict(repo=broken, base=broken_base),
            }
            for form, kwargs in forms.items():
                for cargo_skip in ("true", "false"):
                    with self.subTest(form=form, cargo_skip=cargo_skip):
                        result, _ = self.run_notice(cargo_skip, REASON_CORPUS["v1_command"], **kwargs)
                        self.assertNotIn(b"WORKSPACE-ESCAPER-USED", result.stdout + result.stderr)
                        self.assert_one_notice(result, NOTICE_FALLBACK[cargo_skip])
        finally:
            box.close()

    def expected(self, cargo_skip, reason):
        template = NOTICE_TRUE_TEMPLATE if cargo_skip == "true" else NOTICE_FALSE_TEMPLATE
        line = self.wa.annotation("notice", self.wa.render(template, reason=reason.decode("utf-8", "surrogateescape")))
        return line.encode("utf-8", "backslashreplace") + b"\n"

    def assert_one_notice(self, result, want):
        self.assertEqual(result.returncode, 0, result.stderr[-400:])
        self.assertEqual(result.stdout, want)
        commands, stopped = runner_commands(result.stdout)
        self.assertEqual(len(commands), 1, commands)
        self.assertTrue(commands[0].startswith("::notice::"), commands)
        self.assertFalse(stopped)
        self.assertNotIn(b"##[", result.stdout)

    def test_corpus_both_branches_both_locales(self):
        for name, reason in REASON_CORPUS.items():
            for cargo_skip in ("true", "false"):
                for locale in LOCALES:
                    with self.subTest(value=name, cargo_skip=cargo_skip, locale=locale):
                        result, _ = self.run_notice(cargo_skip, reason, locale)
                        self.assert_one_notice(result, self.expected(cargo_skip, reason))

    def test_large_value_is_bounded(self):
        reason = b"rust-observable-path src/" + b"::error::x%0A##[" * (LARGE_VALUE_BYTES // 16) + b" v3"
        self.assertGreaterEqual(len(reason), LARGE_VALUE_BYTES)
        for cargo_skip in ("true", "false"):
            with self.subTest(cargo_skip=cargo_skip):
                result, took = self.run_notice(cargo_skip, reason)
                self.assertLess(took, LARGE_VALUE_CEILING_SECS)
                self.assert_one_notice(result, self.expected(cargo_skip, reason))

    def test_workspace_escaper_is_never_used(self):
        result, _ = self.run_notice("false", REASON_CORPUS["v1_command"])
        self.assertNotIn(b"WORKSPACE-ESCAPER-USED", result.stdout)
        self.assert_one_notice(result, self.expected("false", REASON_CORPUS["v1_command"]))

    def test_no_trusted_escaper_gives_the_fixed_notice(self):
        box = Sandbox()
        try:
            repo, base = make_trusted_repo(box.root, with_escaper=False)
            for cargo_skip in ("true", "false"):
                with self.subTest(cargo_skip=cargo_skip):
                    trust_dir = box.root / ("trusted-" + cargo_skip)
                    (trust_dir / "scripts" / "ci" / "impact").mkdir(parents=True)
                    prelude = ('cargo_skip="$STUB_SKIP"; cargo_skip_reason="$STUB_REASON"; '
                               'trust_dir="$STUB_TRUST_DIR"; trust_impact="$trust_dir/scripts/ci/impact"; '
                               'trust_ref="$STUB_REF"\n')
                    result, _ = run_bash(prelude + self.span, repo, env_extra={
                        "STUB_SKIP": cargo_skip, "STUB_REASON": REASON_CORPUS["v1_command"],
                        "STUB_TRUST_DIR": str(trust_dir), "STUB_REF": base})
                    self.assertNotIn(b"WORKSPACE-ESCAPER-USED", result.stdout)
                    self.assert_one_notice(result, NOTICE_FALLBACK[cargo_skip])
        finally:
            box.close()

    def test_python_failure_forms_give_the_fixed_notice(self):
        forms = {"python_missing": None, "python_rc_1": "sys.exit(1)",
                 "python_prints_raw_then_fails": "print('::error::raw'); sys.exit(1)"}
        for form, body in forms.items():
            path = self.box.shim_bin("notice-" + form, body)
            for cargo_skip in ("true", "false"):
                with self.subTest(form=form, cargo_skip=cargo_skip):
                    result, _ = self.run_notice(cargo_skip, REASON_CORPUS["v1_command"], path=path)
                    if form == "python_prints_raw_then_fails":
                        # a stand-in that prints and fails still leaves no reason byte and ends with the notice
                        self.assertTrue(result.stdout.endswith(NOTICE_FALLBACK[cargo_skip]), result.stdout)
                        self.assertNotIn(b"##[", result.stdout)
                        self.assertEqual(result.returncode, 0)
                    else:
                        self.assert_one_notice(result, NOTICE_FALLBACK[cargo_skip])


class TrustDir9434(unittest.TestCase):
    """Ruling (a) 1: the cls trust directory is private (mode 700) and never under the workspace."""

    @classmethod
    def setUpClass(cls):
        cls.box = Sandbox()
        cls.repo, cls.base = make_trusted_repo(cls.box.root)
        cls.span = trust_setup_span()

    @classmethod
    def tearDownClass(cls):
        cls.box.close()

    def run_setup(self, runner_temp, tmpdir):
        """Run the real setup lines in the repo (the workspace); return (rc, trust_dir, trusted)."""
        env = {"TMPDIR": str(tmpdir)}
        if runner_temp is not None:
            env["RUNNER_TEMP"] = str(runner_temp)
        script = ('cls_base="$STUB_BASE"\n' + self.span
                  + 'printf "TRUST_DIR=%s\\nTRUSTED=%s\\n" "$trust_dir" "$trusted"\n')
        result, _ = run_bash(script, self.repo, env_extra={**env, "STUB_BASE": self.base})
        values = dict(line.split("=", 1) for line in result.stdout.decode().splitlines() if "=" in line)
        return result, values.get("TRUST_DIR"), values.get("TRUSTED")

    def assert_nothing_in_workspace(self):
        planted = [p for p in self.repo.rglob("*") if "impact-trusted" in p.name]
        self.assertEqual(planted, [], "a trust directory was made under the workspace")

    def assert_private_outside(self, trust_dir, parent):
        path = Path(trust_dir)
        self.assertTrue(path.is_dir(), trust_dir)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), TRUST_DIR_MODE, "trust directory mode")
        real = path.resolve()
        self.assertEqual(real.parent, Path(parent).resolve(), "trust directory not directly under %s" % parent)
        self.assertFalse(real.is_relative_to(self.repo.resolve()), "trust directory under the workspace")
        for trust_file, content in TRUST_FILES.items():
            self.assertEqual((path / "scripts" / "ci" / "impact" / trust_file).read_bytes(), content, trust_file)

    def test_trust_dir_is_mode_700_under_runner_temp(self):
        runner_temp = self.box.root / "runner-temp"
        runner_temp.mkdir()
        result, trust_dir, trusted = self.run_setup(runner_temp, self.box.root)
        self.assertEqual(result.returncode, 0, result.stderr[-400:])
        self.assertEqual(trusted, "true")
        self.assert_private_outside(trust_dir, runner_temp)
        self.assert_nothing_in_workspace()

    def test_trust_dir_is_never_under_the_workspace(self):
        outside = self.box.root / "outside-tmp"
        outside.mkdir()
        inside = self.repo / "inside"
        inside.mkdir(exist_ok=True)
        link = self.box.root / "link-into-workspace"
        if not link.exists():
            link.symlink_to(inside, target_is_directory=True)
        cases = {
            "runner_temp_is_the_workspace": (self.repo, outside, outside),
            "runner_temp_inside_the_workspace": (inside, outside, outside),
            "runner_temp_symlink_into_the_workspace": (link, outside, outside),
            "runner_temp_unset": (None, outside, outside),
        }
        for name, (runner_temp, tmpdir, parent) in cases.items():
            with self.subTest(case=name):
                result, trust_dir, trusted = self.run_setup(runner_temp, tmpdir)
                self.assertEqual(result.returncode, 0, result.stderr[-400:])
                self.assertEqual(trusted, "true")
                self.assert_private_outside(trust_dir, parent)
                self.assert_nothing_in_workspace()

    def test_no_private_place_outside_the_workspace_fails_closed(self):
        inside = self.repo / "inside"
        inside.mkdir(exist_ok=True)
        for name, runner_temp in (("runner_temp_unset", None), ("runner_temp_is_the_workspace", self.repo),
                                  ("runner_temp_missing", self.box.root / "no-such-dir")):
            with self.subTest(case=name):
                result, trust_dir, trusted = self.run_setup(runner_temp, inside)
                self.assertEqual(result.returncode, 0, result.stderr[-400:])
                self.assertEqual((trust_dir, trusted), ("", "false"))
                self.assert_nothing_in_workspace()


class ShardLogs9433(unittest.TestCase):
    """#9433: each shard log reaches the runner only between stop-commands markers."""

    @classmethod
    def setUpClass(cls):
        cls.box = Sandbox()
        cls.span = shard_span()

    @classmethod
    def tearDownClass(cls):
        cls.box.close()

    def run_shards(self, logs, path=None, locale="C.UTF-8"):
        """``logs`` maps shard -> bytes, ``None`` (missing) or ``"dir"`` (unreadable: a directory in its place)."""
        sd = Path(tempfile.mkdtemp(prefix="sd-", dir=str(self.box.root)))
        for shard, content in logs.items():
            target = sd / ("%s.log" % shard)
            if content == "dir":
                target.mkdir()
            elif content == "mode000":
                target.write_bytes(b"::error::hidden\n")
                target.chmod(0)
            elif content is not None:
                target.write_bytes(content)
        script = ('shards_9433() {\nlocal sd="$STUB_SD" n\n' + self.span + '}\nshards_9433\necho "%s"\n'
                  % AFTER_MARK)
        return run_bash(script, sd, path=path, locale=locale, env_extra={"STUB_SD": str(sd)})

    def check_run(self, logs, result):
        """Every block well formed, exit code as the base (cat fails => set -e exit 1, else 0)."""
        out = result.stdout
        pos = 0
        tokens = []
        failing = False
        for shard in SHARDS:
            content = logs[shard]
            group = ("::group::[#6344] %s shard output\n" % shard).encode()
            self.assertTrue(out.startswith(group, pos), "group line of %s missing at %d: %r" % (shard, pos, out[pos:pos + 120]))
            pos += len(group)
            readable = isinstance(content, bytes)
            # a failed print ends with a newline from the step, so the end line starts its own line
            token, pos = take_block(self, out, pos, content if readable else b"\n")
            tokens.append(token)
            self.assertTrue(out.startswith(b"::endgroup::\n", pos), "endgroup of %s missing" % shard)
            pos += len(b"::endgroup::\n")
            if not readable:
                failing = True
                break
        if failing:
            self.assertEqual(result.returncode, 1, "exit code differs from the base (cat failure under -e)")
            self.assertEqual(out[pos:], b"")
        else:
            self.assertEqual(result.returncode, 0, result.stderr[-400:])
            self.assertEqual(out[pos:], (AFTER_MARK + "\n").encode())
        self.assertEqual(len(set(tokens)), len(tokens), "a token was reused across blocks")
        for token in tokens:
            self.assertNotIn(token, result.stderr)
        commands, stopped = runner_commands(out)
        self.assertFalse(stopped, "the runner would stay in stop-commands mode")
        for line in commands:
            self.assertTrue(line.startswith(("::group::[#6344] ", "::endgroup::", "::stop-commands::", "<end ")),
                            "runner would act on %r" % line[:120])
        return tokens

    def test_hostile_log_corpus(self):
        for name, content in LOG_CORPUS.items():
            with self.subTest(log=name):
                logs = {shard: content for shard in SHARDS}
                result, took = self.run_shards(logs)
                self.assertLess(took, MIB_CEILING_SECS)
                self.check_run(logs, result)

    def test_hostile_log_corpus_c_locale(self):
        for name in ("v2_error", "non_utf8", "cr_only", "no_final_newline"):
            with self.subTest(log=name):
                logs = {shard: LOG_CORPUS[name] for shard in SHARDS}
                result, _ = self.run_shards(logs, locale="C")
                self.check_run(logs, result)

    def test_previous_run_token_cannot_end_the_block(self):
        first_logs = {shard: b"plain\n" for shard in SHARDS}
        first, _ = self.run_shards(first_logs)
        previous = self.check_run(first_logs, first)
        hostile = {shard: b"::" + previous[i] + b"::\n::error::after-previous\n" for i, shard in enumerate(SHARDS)}
        second, _ = self.run_shards(hostile)
        tokens = self.check_run(hostile, second)
        self.assertFalse(set(tokens) & set(previous), "two runs gave the same token")

    def test_missing_and_unreadable_logs(self):
        cases = {"missing": None, "directory": "dir"}
        if os.geteuid() != 0:
            cases["mode_000"] = "mode000"
        for name, bad in cases.items():
            for index in range(len(SHARDS)):
                with self.subTest(case=name, shard=SHARDS[index]):
                    logs = {shard: b"::error::x\n" for shard in SHARDS}
                    logs[SHARDS[index]] = bad
                    result, _ = self.run_shards(logs)
                    self.assertNotIn(b"::error::hidden", result.stdout)
                    self.check_run(logs, result)

    def test_token_failure_forms_fail_closed_on_the_print_only(self):
        forms = {
            "python_missing": None,
            "python_rc_1": "sys.exit(1)",
            "token_empty": "print('')",
            "token_short": "print('0123')",
            "token_guessable_word": "print('pause')",
        }
        logs = {shard: b"::error::must-not-print\n##[group]x\n" for shard in SHARDS}
        for form, body in forms.items():
            with self.subTest(form=form):
                result, _ = self.run_shards(logs, path=self.box.shim_bin("shard-" + form, body))
                want = b"".join(("::group::[#6344] %s shard output\n" % shard).encode()
                                + (SHARD_FALLBACK % shard).encode() + b"::endgroup::\n" for shard in SHARDS)
                self.assertEqual(result.stdout, want + (AFTER_MARK + "\n").encode())
                self.assertEqual(result.returncode, 0)

    def test_print_that_fails_half_way_still_ends_the_block(self):
        """Ruling (a) 3: the copy dies mid-line (no finally of its own runs); the end line still starts its own
        line and the step exit code is that of the failed print (base: ``cat`` failing under -e = 1)."""
        body = ("import os, secrets\n"
                "if any('secrets' in a for a in sys.argv):\n    print(secrets.token_hex(16))\n"
                "else:\n    os.write(1, %r)\n    os._exit(1)" % PARTIAL_PRINT)
        logs = {shard: b"::error::x\n" for shard in SHARDS}
        result, _ = self.run_shards(logs, path=self.box.shim_bin("shard-half-way", body))
        out = result.stdout
        group = ("::group::[#6344] %s shard output\n" % SHARDS[0]).encode()
        self.assertTrue(out.startswith(group), out[:120])
        _, pos = take_block(self, out, len(group), PARTIAL_PRINT)
        self.assertEqual(out[pos:], b"::endgroup::\n")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(runner_commands(out)[1], False, "the runner would stay in stop-commands mode")


class ClassSiblings9433(unittest.TestCase):
    """The same class at the changed-file list (cls), the selector log (impact) and the fed db name cut."""

    @classmethod
    def setUpClass(cls):
        cls.box = Sandbox()

    @classmethod
    def tearDownClass(cls):
        cls.box.close()

    def test_changed_file_list_is_inside_a_block(self):
        for name, changed in CHANGED_CORPUS.items():
            with self.subTest(changed=name):
                prelude = 'changed="$STUB_CHANGED"; cls_base=0123456789abcdef0123456789abcdef01234567\n'
                result, _ = run_bash(prelude + changed_span(), self.box.root, env_extra={"STUB_CHANGED": changed})
                self.assertEqual(result.returncode, 0)
                out = result.stdout
                header_end = out.index(b"\n") + 1
                self.assertTrue(out.startswith(b"--- Changed files vs classification base "))
                _, end = take_block(self, out, header_end, changed.encode() + b"\n")
                self.assertEqual(out[end:], b"")
                commands, stopped = runner_commands(out)
                self.assertFalse(stopped)
                self.assertTrue(all(c.startswith(("::stop-commands::", "<end ")) for c in commands), commands)

    def test_changed_file_list_without_token(self):
        path = self.box.shim_bin("changed", "sys.exit(1)")
        prelude = 'changed="$STUB_CHANGED"; cls_base=0123456789abcdef0123456789abcdef01234567\n'
        result, _ = run_bash(prelude + changed_span(), self.box.root, path=path,
                             env_extra={"STUB_CHANGED": CHANGED_CORPUS["v2_name"]})
        self.assertEqual(result.returncode, 0)
        header_end = result.stdout.index(b"\n") + 1
        self.assertEqual(result.stdout[header_end:], CHANGED_FALLBACK)

    def run_changed(self, changed, prelude_extra=""):
        """The changed-list span with ``changed`` read from a file (a 1 MiB value is over the argv limit)."""
        value = self.box.root / ("changed-%d" % time.monotonic_ns())
        value.write_bytes(changed)
        prelude = (prelude_extra + 'changed=$(cat "$STUB_CHANGED_FILE"); '
                   'cls_base=0123456789abcdef0123456789abcdef01234567\n')
        return run_bash(prelude + changed_span(), self.box.root, env_extra={"STUB_CHANGED_FILE": str(value)})

    def test_changed_list_of_one_mib_without_a_newline(self):
        changed = b"src/" + b"A" * MIB + b"::error::x##[group]y"
        result, took = self.run_changed(changed)
        self.assertLess(took, MIB_CEILING_SECS)
        self.assertEqual(result.returncode, 0, result.stderr[-400:])
        out = result.stdout
        _, end = take_block(self, out, out.index(b"\n") + 1, changed)
        self.assertEqual(out[end:], b"")
        self.assertEqual(runner_commands(out)[1], False)

    def test_changed_list_print_that_fails_half_way_still_ends_the_block(self):
        """Ruling (a) 3: the print writes part of a line and fails; the end line still starts its own line and
        the step exit code is that of the failed print (base: ``echo "$changed"`` failing under -e = 1)."""
        fail = "printf() { builtin printf '%%s' '%s'; return 1; }\n" % PARTIAL_PRINT.decode()
        result, _ = self.run_changed(CHANGED_CORPUS["v2_name"].encode(), prelude_extra=fail)
        out = result.stdout
        _, end = take_block(self, out, out.index(b"\n") + 1, PARTIAL_PRINT)
        self.assertEqual(out[end:], b"")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(runner_commands(out)[1], False)

    def test_impact_print_exit_code_equals_the_base(self):
        """Ruling (a) 2: the BASE step text (a028c45e) and the HEAD step text against a readable, a missing and
        an unreadable log; exit codes pinned per IMPACT_RC_TABLE (equal, except a case pending the ruling)."""
        base_text = base_workflow_text()
        if base_text is not None:
            self.assertEqual(impact_span(base_text), BASE_IMPACT_SPAN, "the base step text is not the pinned one")
        readable = self.box.root / "impact-rc-readable.log"
        readable.write_bytes(b"selected ##[error]x\n::error::y\n")
        unreadable = self.box.root / "impact-rc-unreadable.log"
        unreadable.write_bytes(b"::error::hidden\n")
        unreadable.chmod(0)
        self.assertNotEqual(os.geteuid(), 0, "run as a user that mode 000 denies (root reads it)")
        logs = {"readable": readable, "missing": self.box.root / "impact-rc-missing.log", "unreadable": unreadable}
        for name, log in logs.items():
            with self.subTest(log=name):
                got = []
                outs = []
                for text in (BASE_IMPACT_SPAN, impact_span()):
                    result, _ = run_bash('impact_log="$STUB_LOG"\n' + text + 'echo "%s"\n' % AFTER_MARK,
                                         self.box.root, env_extra={"STUB_LOG": str(log)})
                    got.append(result.returncode)
                    outs.append(result.stdout)
                self.assertEqual(tuple(got), IMPACT_RC_TABLE[name], "(base rc, head rc) for a %s log" % name)
                if name not in IMPACT_RC_PENDING_RULING:
                    self.assertEqual(got[0], got[1], "head exit code differs from the base for a %s log" % name)
                if name == "readable":
                    self.assertEqual(outs[0], outs[1].replace(b"# #[", b"##["))
                else:
                    self.assertEqual(outs, [b"", b""], "a failing print must print nothing and stop the step")

    @staticmethod
    def impact_expected(log):
        """The first 200 LF lines, "##[" -> "# #[" and "::" -> ": :" left to right, final newline added."""
        lines = log.split(b"\n")
        kept = [line + b"\n" for line in lines[:-1]] + ([lines[-1]] if lines[-1] else [])
        shown = b"".join(line.replace(b"##[", b"# #[").replace(b"::", b": :") for line in kept[:IMPACT_LINES])
        return shown + (b"\n" if shown and not shown.endswith(b"\n") else b"")

    def test_selector_log_is_spaced(self):
        corpus = {
            "v1_anywhere": b"selected: x ##[error]y\n",
            "v1_repeated_hash": b"###[error]x ####[group]y\n",
            "v2_line": b"::error::x\n",
            "v2_triple_colon": b":::error::x\n  ::warning::y\n",
            "no_final_newline": b"a\n##[error]tail",
            "over_200_lines": b"".join(b"line %d ##[error] ::error::\n" % i for i in range(250)),
            "cr_only": b"a\r##[error]b\r::error::c\r",
            "non_utf8": b"\xff##[error]\xfe::error::x\n",
            "large": b"##[" * (LARGE_VALUE_BYTES // 3) + b"\n",
            "mib_no_newline_at_all": b"##[" + b"A" * MIB + b"::error::x",
            "crlf": b"a\r\n::error::b\r\n##[group]c\r\n",
            "empty": b"",
        }
        for name, log in corpus.items():
            for locale in LOCALES:
                with self.subTest(log=name, locale=locale):
                    log_file = self.box.root / ("impact-%s.log" % name)
                    log_file.write_bytes(log)
                    result, took = run_bash('impact_log="$STUB_LOG"\n' + impact_span(), self.box.root,
                                            locale=locale, env_extra={"STUB_LOG": str(log_file)})
                    self.assertLess(took, LARGE_VALUE_CEILING_SECS)
                    self.assertEqual(result.returncode, 0, result.stderr[-400:])
                    self.assertEqual(result.stdout, self.impact_expected(log))
                    self.assertEqual(runner_commands(result.stdout), ([], False))

    def test_selector_log_unreadable_fails_like_sed(self):
        for name, python in (("directory", None), ("python_rc_1", "sys.exit(1)")):
            with self.subTest(case=name):
                log_file = self.box.root / ("impact-bad-%s.log" % name)
                if python is None:
                    log_file.mkdir()
                    path = None
                else:
                    log_file.write_bytes(b"##[error]x\n::error::y\n")
                    path = self.box.shim_bin("impact-" + name, python)
                result, _ = run_bash('impact_log="$STUB_LOG"\n' + impact_span(), self.box.root, path=path,
                                     env_extra={"STUB_LOG": str(log_file)})
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, b"")

    def test_fed_db_name_is_cut_in_bytes(self):
        run_id = "1234567890" + "é" * 30
        leg = "Enterprise-Fed (Linux)"
        leg_sanitized = "".join(ch if ch in "abcdefghijklmnopqrstuvwxyz0123456789" else "_" for ch in leg.lower())
        full = ("ai_memory_test_ci_%s_%s_%s" % (run_id, "1", leg_sanitized)).encode("utf-8")
        want = b"CI_FED_DB=" + full[:FED_DB_MAX_BYTES] + b"\n"
        for locale in LOCALES:
            with self.subTest(locale=locale):
                env_file = self.box.root / ("github-env-%s" % locale)
                env_file.write_bytes(b"")
                result, _ = run_bash("set -euo pipefail\n" + fed_span(), self.box.root, locale=locale, env_extra={
                    "LEG": leg, "GITHUB_RUN_ID": run_id.encode("utf-8"), "GITHUB_RUN_ATTEMPT": "1",
                    "GITHUB_ENV": str(env_file)})
                self.assertEqual(result.returncode, 0, result.stderr[-400:])
                self.assertEqual(env_file.read_bytes(), want)


if __name__ == "__main__":
    unittest.main()
