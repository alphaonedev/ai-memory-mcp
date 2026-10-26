#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Runtime echo canary of the tier-credential pins (#8187, round 29; 3-agent vote (6def5ab6), option B).

The claim of the pins is that no test code can echo the CI tier credential.  A static scan cannot prove that for Python (four
rounds of review each found a new class), so the claim is made here, at runtime, the way the reviewers test it.  The static
scan of the test module stays as a fail-closed PRE-CHECK that refuses unknown shapes; it is NOT claimed complete, this canary
is the claim.

1. A throwaway copy of the repository (``scripts`` and ``.github``) gets a unique MARKER as the value of an ``env`` entry of
   every ``env`` block of every workflow, and the module's own ``--write-pins`` regenerates the pins, so the marker travels
   the real loading path (``tier_yaml_8187.StrictLoader``, the pins, the text views).
2. The WHOLE test module runs in a copy of that tree as a subprocess, under unittest and under pytest, from two working
   directories, with file descriptors 1 and 2 redirected to files (children inherit them), ``PYTHONUNBUFFERED=1``, a scratch
   home and temp directory, and an environment sentinel so the child does not start a canary of its own.
3. The FORCED mode makes every test fail after its body (a trace function raises at the ``return`` event of the test method)
   and makes EVERY ``assert*`` call echo its operands to stderr, as a failing assertion would print them (the same reprs the
   failure message and its diff are built from).  Frame locals are not part of the authoritative mode: a runner option that
   lists them (``pytest --showlocals``, unittest ``tb_locals``) is the reader's choice, and the tests hold workflow text in locals
   by design.  ``TIER_CANARY_LOCALS_8187=1`` runs that informational leg as well (it is NOT claimed clean).
4. Every captured byte (stdout, stderr, the junit report and every file created or changed under the copy) is searched for the
   marker under the finite NAMED transform set ``CANARY_TRANSFORMS``.
5. Any hit fails, naming only the transform, the run and the byte offset: never the text around it, never the marker.

``planted_catalogue`` is the self-test: deliberate echoes (one per transform, the 31 shapes and 12 exempt-function inserts the
security reviewer found past the static scan) are planted in a throwaway module and each must be caught.

Standard library only; Python 3.9+.
"""
import base64
import codecs
import concurrent.futures
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import time
from pathlib import Path

CANARY_CHILD_ENV = "TIER_CANARY_CHILD_8187"
CANARY_FULL_ENV = "TIER_CANARY_FULL_8187"
# Fail-closed skip: the canary runs whenever this is absent (local runs, the canary job); only an explicit "1" skips it.
CANARY_SKIP_ENV = "TIER_CANARY_8187_SKIP"
CANARY_FORCE_ENV = "TIER_CANARY_FORCE_8187"
CANARY_EXTRA_PATH_ENV = "TIER_CANARY_EXTRA_PATH_8187"
CANARY_MODULE = "test_ci_tier_password_check_6181.py"
CANARY_ENV_KEY = "CANARY_CREDENTIAL"
CANARY_RUNNERS = ("unittest", "pytest")
CANARY_CWDS = ("root", "tests")
CANARY_MODES = ("normal", "forced")
CANARY_RUN_TIMEOUT_SECONDS = 3300
CANARY_PLANT_TIMEOUT_SECONDS = 600
CANARY_COPY_DIRS = ("scripts", ".github")
CANARY_IGNORE = ("__pycache__", ".local-runs", "*.pyc", ".git", "target")
CANARY_WORKFLOW_DIR = ".github/workflows"

# the finite, named transform set (decision: a finite named transform set over an open one because the canary detects an
# echo and the pre-check refuses the encoders)
CANARY_TRANSFORMS = (
    "identity", "upper", "lower", "reversed", "hex", "base64-standard", "base64-urlsafe", "codepoints-space",
    "codepoints-comma", "rot13", "percent-encoding", "json-escape", "repr", "whitespace-stripped",
)
_WHITESPACE = frozenset(b" \t\r\n\x0b\x0c")


def mint_marker():
    """A random marker of mixed case and digits (so upper, lower and rot13 differ from the plain form)."""
    return "Cnry" + secrets.token_hex(16)


def marker_label(marker):
    """The only form of a marker that is ever logged."""
    return hashlib.sha256(marker.encode("utf-8")).hexdigest()


def _base64_needles(marker, altchars=None):
    """The base64 of the marker at the three alignments a longer text puts it at (the first and the last group are dropped,
    they depend on the neighbours)."""
    raw = marker.encode("ascii")
    needles = []
    for pad in range(3):
        encoded = base64.b64encode(b"\0" * pad + raw, altchars=altchars)
        needles.append(encoded[(4 if pad else 0):-4])
    return needles


def transform_needles(marker):
    """``{name: (needles, fold)}``: the byte strings a capture must not hold; ``fold`` says to compare lower case.  The
    whitespace-stripped transform is applied to the data, not to the marker (see ``scan_bytes``)."""
    raw = marker.encode("ascii")
    return {
        "identity": ([raw], False),
        "upper": ([marker.upper().encode("ascii")], False),
        "lower": ([marker.lower().encode("ascii")], False),
        "reversed": ([marker[::-1].encode("ascii")], False),
        "hex": ([raw.hex().encode("ascii")], True),
        "base64-standard": (_base64_needles(marker), False),
        "base64-urlsafe": (_base64_needles(marker, b"-_"), False),
        "codepoints-space": ([" ".join(str(ord(c)) for c in marker).encode("ascii")], False),
        "codepoints-comma": ([",".join(str(ord(c)) for c in marker).encode("ascii")], False),
        "rot13": ([codecs.encode(marker, "rot13").encode("ascii")], False),
        "percent-encoding": ([("".join("%%%02x" % ord(c) for c in marker)).encode("ascii")], True),
        "json-escape": ([("".join("\\u%04x" % ord(c) for c in marker)).encode("ascii")], True),
        "repr": ([repr(list(marker)).encode("ascii")], False),
    }


def scan_bytes(data, marker):
    """``[(transform name, byte offset)]`` of the first hit of every transform of ``CANARY_TRANSFORMS`` in ``data``.  The last
    transform finds the marker once every whitespace byte is removed (a per-character split); its offset is in the stripped
    stream.  Nothing but the name and the offset leaves this function."""
    hits = []
    lowered = data.lower()
    for name, (needles, fold) in transform_needles(marker).items():
        hay = lowered if fold else data
        for needle in needles:
            at = hay.find(needle.lower() if fold else needle)
            if at >= 0:
                hits.append((name, at))
                break
    stripped = bytes(b for b in data if b not in _WHITESPACE)
    at = stripped.find(marker.encode("ascii"))
    if at >= 0 and not any(name == "identity" for name, _ in hits):
        hits.append(("whitespace-stripped", at))
    return hits


# --------------------------------------------------------------------------------------------------------------------
# interpreters

class Interpreter:
    def __init__(self, path, version, has_yaml, has_pytest):
        self.path, self.version, self.has_yaml, self.has_pytest = path, version, has_yaml, has_pytest
        self.yaml_dir = None  # a directory that holds a pure-Python PyYAML for an interpreter without its own

    @property
    def tag(self):
        return "py%d.%d.%d" % self.version

    @property
    def can_run(self):
        return self.has_yaml or self.yaml_dir is not None


_PROBE = ("import sys, importlib.util as u;"
          "print(*sys.version_info[:3]);"
          "print(u.find_spec('yaml') is not None, u.find_spec('pytest') is not None);"
          "y = u.find_spec('yaml');"
          "print(list(y.submodule_search_locations)[0] if y and y.submodule_search_locations else '')")


def probe_interpreter(path):
    try:
        done = subprocess.run([path, "-I", "-c", _PROBE], capture_output=True, text=True, timeout=60, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    lines = done.stdout.split("\n")
    if done.returncode != 0 or len(lines) < 3:
        return None
    flags = lines[1].split()
    found = Interpreter(path, tuple(int(n) for n in lines[0].split()), flags[0] == "True", flags[1] == "True")
    found.yaml_package = lines[2]
    return found


def discover_interpreters():
    """Every distinct CPython on this host (``sys.executable``, ``python3``, ``python3.8`` .. ``python3.15``) with its version
    and whether it can import PyYAML (needed by the module) and pytest.  An interpreter without PyYAML borrows the pure-Python
    package of one that has it (PyYAML falls back to its Python loader when the C extension is missing)."""
    names = [sys.executable, shutil.which("python3")] + [shutil.which("python3.%d" % minor) for minor in range(8, 16)]
    seen, found = set(), []
    for name in names:
        if not name:
            continue
        real = os.path.realpath(name)
        if real in seen:
            continue
        seen.add(real)
        probed = probe_interpreter(name)
        if probed is not None:
            found.append(probed)
    donors = [item for item in found if item.has_yaml and getattr(item, "yaml_package", "")]
    for item in found:
        if not item.has_yaml and donors:
            item.yaml_dir = str(Path(donors[-1].yaml_package).parent)
    return sorted(found, key=lambda item: item.version)


def pick_interpreters(found):
    """The lowest and the highest interpreter that can run the module; one entry when they coincide."""
    usable = [item for item in found if item.can_run]
    if not usable:
        return []
    low, high = usable[0], usable[-1]
    return [low] if low.version == high.version else [low, high]


# --------------------------------------------------------------------------------------------------------------------
# the copy

FORCE_SOURCE = '''"""Forced-failure hook (canary): a trace function raises at the return event of every test body, and every assert*
call echoes its operands to stderr, as the message of a failing assertion would."""
import functools
import sys
import unittest

ECHO_SKIP = frozenset(("assertRaises", "assertRaisesRegex", "assertWarns", "assertWarnsRegex", "assertLogs", "assertNoLogs"))


def echoing(name, original):
    @functools.wraps(original)
    def wrapper(self, *args, **kwargs):
        result = original(self, *args, **kwargs)
        # a failing assertTrue / assertIsNotNone shows a falsy / None operand (no text): only the message can carry data
        judged = args[1:] if name in ("assertTrue", "assertIsNotNone") else args
        shown = [repr(arg) for arg in judged] + ["%s=%r" % pair for pair in kwargs.items()]
        sys.stderr.write("FORCED %s(%s)\\n" % (name, ", ".join(shown)))
        return result

    return wrapper


def install():
    for name in dir(unittest.TestCase):
        if name.startswith("assert") and name not in ECHO_SKIP and callable(getattr(unittest.TestCase, name)):
            setattr(unittest.TestCase, name, echoing(name, getattr(unittest.TestCase, name)))

    def forced(self, method):
        code = getattr(getattr(method, "__func__", method), "__code__", None)

        def local(frame, event, arg):
            if event == "return":
                raise AssertionError("forced failure after the test body")
            return local

        def glob(frame, event, arg):
            return local if frame.f_code is code else None

        sys.settrace(glob)
        try:
            return method()
        finally:
            sys.settrace(None)

    unittest.TestCase._callTestMethod = forced
'''

UNITTEST_RUNNER_SOURCE = '''"""unittest runner of the canary: loads one module (or one named test), runs it verbosely to stderr and records the ids that
ran and were skipped."""
import json
import os
import sys
import unittest

path, out, mode = sys.argv[1], sys.argv[2], sys.argv[3]
only = sys.argv[4] if len(sys.argv) > 4 else None
here = os.path.dirname(os.path.abspath(path))
sys.path.insert(0, here)
extra = os.environ.get("TIER_CANARY_EXTRA_PATH_8187")
if extra:
    sys.path.append(extra)
forced = mode == "forced"
if forced:
    sys.path.insert(0, os.environ["TIER_CANARY_HOOK_DIR_8187"])
    import canary_force
    canary_force.install()


class Result(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.ran_ids, self.skipped_ids = [], []

    def startTest(self, test):
        self.ran_ids.append(test.id())
        super().startTest(test)

    def addSkip(self, test, reason):
        self.skipped_ids.append(test.id())
        super().addSkip(test, reason)


if only:
    suite = unittest.defaultTestLoader.loadTestsFromName(only)
else:
    suite = unittest.defaultTestLoader.discover(here, pattern=os.path.basename(path), top_level_dir=here)
runner = unittest.TextTestRunner(stream=sys.stderr, verbosity=2, tb_locals=forced and os.environ.get("TIER_CANARY_LOCALS_8187") == "1",
                                 resultclass=Result)
result = runner.run(suite)
with open(out, "w", encoding="utf-8") as handle:
    json.dump({"ran": result.ran_ids, "skipped": result.skipped_ids, "failures": len(result.failures),
               "errors": len(result.errors), "total": result.testsRun}, handle)
sys.exit(0)
'''

CONFTEST_SOURCE = '''import os
import sys

if os.environ.get("TIER_CANARY_FORCE_8187") == "1":
    sys.path.insert(0, os.environ["TIER_CANARY_HOOK_DIR_8187"])
    import canary_force  # noqa: E402

    canary_force.install()
'''


def inject_marker(workflows, marker):
    """Add ``CANARY_CREDENTIAL: <marker>`` to every block-style ``env:`` mapping of every workflow; the number of entries added."""
    added = 0
    for path in sorted(Path(workflows).glob("*.yml")):
        rows = path.read_text(encoding="utf-8").split("\n")
        out, at = [], 0
        while at < len(rows):
            row = rows[at]
            out.append(row)
            at += 1
            if re.match(r"^\s*env:\s*$", row):
                base = len(row) - len(row.lstrip())
                look = at
                while look < len(rows) and (not rows[look].strip() or rows[look].lstrip().startswith("#")):
                    look += 1
                if look < len(rows):
                    indent = len(rows[look]) - len(rows[look].lstrip())
                    if indent > base:
                        out.append("%s%s: %s" % (" " * indent, CANARY_ENV_KEY, marker))
                        added += 1
        path.write_text("\n".join(out), encoding="utf-8")
    return added


def tree_snapshot(root):
    """``{relative path: sha256}`` of every file under ``root``."""
    found = {}
    for path in sorted(Path(root).rglob("*")):
        if path.is_file() and not path.is_symlink():
            found[str(path.relative_to(root))] = hashlib.sha256(path.read_bytes()).hexdigest()
    return found


def child_env(copy, interpreter=None, forced=False):
    """The environment of every child: the sentinel, unbuffered output, no bytecode, a scratch home and temp directory."""
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(Path(copy) / "home"), "TMPDIR": str(Path(copy) / "tmp"),
           "LANG": "C.UTF-8", "PYTHONUNBUFFERED": "1", "PYTHONDONTWRITEBYTECODE": "1", CANARY_CHILD_ENV: "1",
           "TIER_CANARY_HOOK_DIR_8187": str(Path(copy) / "hooks")}
    if forced:
        env[CANARY_FORCE_ENV] = "1"
        if os.environ.get("TIER_CANARY_LOCALS_8187") == "1":
            env["TIER_CANARY_LOCALS_8187"] = "1"
    if interpreter is not None and interpreter.yaml_dir and not interpreter.has_yaml:
        env[CANARY_EXTRA_PATH_ENV] = str(Path(copy) / "site")
    return env


def build_base(repo_root, target, marker, interpreter):
    """The throwaway repository: ``scripts`` and ``.github`` of ``repo_root`` with the marker injected, the pins regenerated by
    the module's own ``--write-pins`` and the hook files.  Returns ``(entries injected, write-pins capture, its return code)``."""
    target = Path(target)
    shutil.rmtree(target, ignore_errors=True)
    target.mkdir(parents=True)
    for name in CANARY_COPY_DIRS:
        shutil.copytree(Path(repo_root) / name, target / name, ignore=shutil.ignore_patterns(*CANARY_IGNORE))
    for name in ("home", "tmp", "hooks"):
        (target / name).mkdir()
    if interpreter.yaml_dir and not interpreter.has_yaml:
        (target / "site").mkdir()
        shutil.copytree(Path(interpreter.yaml_dir) / "yaml", target / "site" / "yaml",
                        ignore=shutil.ignore_patterns("__pycache__", "*.so"))
    added = inject_marker(target / CANARY_WORKFLOW_DIR, marker)
    hooks = target / "hooks"
    (hooks / "canary_force.py").write_text(FORCE_SOURCE, encoding="utf-8")
    (hooks / "canary_unittest_runner.py").write_text(UNITTEST_RUNNER_SOURCE, encoding="utf-8")
    (target / "scripts" / "test" / "conftest.py").write_text(CONFTEST_SOURCE, encoding="utf-8")
    module = target / "scripts" / "test" / CANARY_MODULE
    done = subprocess.run([interpreter.path, "-I", "-c", _WRITE_PINS_LAUNCH, str(module)], cwd=str(target),
                          env=child_env(target, interpreter), capture_output=True, check=False, timeout=900)
    return added, done.stdout + done.stderr, done.returncode


# runs the module's own ``--write-pins`` with the borrowed PyYAML on the path (``-I`` drops PYTHON* variables)
_WRITE_PINS_LAUNCH = ("import os, sys, runpy;"
                      "extra = os.environ.get('%s');"
                      "extra and sys.path.append(extra);"
                      "sys.argv = [sys.argv[1], '--write-pins'];"
                      "runpy.run_path(sys.argv[0], run_name='__main__')" % CANARY_EXTRA_PATH_ENV)


class RunResult:
    def __init__(self, label):
        self.label = label
        self.returncode = None
        self.seconds = 0.0
        self.hits = []        # (transform name, channel, byte offset)
        self.counts = {}      # ran, skipped, failures, errors
        self.ran = set()
        self.skipped = set()
        self.error = ""


def module_target(cwd_mode, name=CANARY_MODULE):
    return name if cwd_mode == "tests" else "scripts/test/" + name


def command_for(interpreter, runner, cwd_mode, mode, copy, out_dir, name=CANARY_MODULE, only=None):
    """The child command; its working directory is ``copy`` for ``root`` and ``copy/scripts/test`` for ``tests``."""
    target = module_target(cwd_mode, name)
    if runner == "unittest":
        cmd = [interpreter.path, "-I", str(Path(copy) / "hooks" / "canary_unittest_runner.py"), target,
               str(Path(out_dir) / "unittest.json"), mode]
        if only:
            cmd.append(only)
        return cmd
    cmd = [interpreter.path, "-I", "-m", "pytest", "-p", "no:cacheprovider", "-q", "-rs", target + ("::" + only if only else ""),
           "--junitxml=" + str(Path(out_dir) / "junit.xml")]
    if mode == "forced":
        cmd += ["--tb=long"] + (["--showlocals"] if os.environ.get("TIER_CANARY_LOCALS_8187") == "1" else [])
    return cmd


def parse_junit(path):
    """``(ran ids, skipped ids)`` from a junit report."""
    ran, skipped = set(), set()
    if not Path(path).exists():
        return ran, skipped
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    for match in re.finditer(r"<testcase\b([^>]*?)(/>|>(.*?)</testcase>)", text, re.S):
        attrs = dict(re.findall(r'(\w+)="([^"]*)"', match.group(1)))
        ident = attrs.get("classname", "") + "." + attrs.get("name", "")
        ran.add(ident)
        if match.group(3) and "<skipped" in match.group(3):
            skipped.add(ident)
    return ran, skipped


def run_child(leg, copy, snapshot, marker, out_root, name=CANARY_MODULE, only=None, scan_files=True, timeout=None):
    """One child run in ``copy``; the channels (stdout, stderr, junit, new or changed files) are scanned for the marker.
    ``leg`` is ``(interpreter, runner, cwd_mode, mode)``."""
    interpreter, runner, cwd_mode, mode = leg
    label = "%s/%s/cwd=%s/%s" % (interpreter.tag, runner, cwd_mode, mode)
    if only or name != CANARY_MODULE:
        label += "/" + name.replace(".py", "")
    result = RunResult(label)
    out_dir = Path(out_root) / label.replace("/", "_").replace("=", "-")
    out_dir.mkdir(parents=True, exist_ok=True)
    cwd = Path(copy) if cwd_mode == "root" else Path(copy) / "scripts" / "test"
    cmd = command_for(interpreter, runner, cwd_mode, mode, copy, out_dir, name, only)
    started = time.time()
    try:
        with open(out_dir / "stdout.bin", "wb") as out, open(out_dir / "stderr.bin", "wb") as err:
            done = subprocess.run(cmd, cwd=str(cwd), env=child_env(copy, interpreter, mode == "forced"), stdin=subprocess.DEVNULL,
                                  stdout=out, stderr=err, timeout=timeout or CANARY_RUN_TIMEOUT_SECONDS, check=False)
        result.returncode = done.returncode
    except subprocess.TimeoutExpired:
        result.error = "timed out"
    result.seconds = time.time() - started
    channels = [("stdout", (out_dir / "stdout.bin").read_bytes()), ("stderr", (out_dir / "stderr.bin").read_bytes())]
    if (out_dir / "junit.xml").exists():
        channels.append(("junit", (out_dir / "junit.xml").read_bytes()))
    if scan_files:
        now = tree_snapshot(copy)
        for index, (path, digest) in enumerate(sorted(now.items())):
            if snapshot.get(path) != digest and not path.startswith("hooks/") and "/plant_" not in path:
                channels.append(("file#%d" % index, (Path(copy) / path).read_bytes()))
    for channel, data in channels:
        for transform, offset in scan_bytes(data, marker):
            result.hits.append((transform, channel, offset))
    if runner == "unittest" and (out_dir / "unittest.json").exists():
        data = json.loads((out_dir / "unittest.json").read_text(encoding="utf-8"))
        result.ran, result.skipped = set(data["ran"]), set(data["skipped"])
        result.counts = {"ran": data["total"], "skipped": len(data["skipped"]), "failures": data["failures"], "errors": data["errors"]}
    elif runner == "pytest":
        result.ran, result.skipped = parse_junit(out_dir / "junit.xml")
        result.counts = {"ran": len(result.ran), "skipped": len(result.skipped)}
    return result


def default_plan(interpreter):
    """What runs wherever the module runs in CI: the WHOLE module once, forced mode (every test body runs and then fails, so the
    output of the passing and of the failing run are both produced), current interpreter, unittest, from the repository root."""
    return [(interpreter, "unittest", "root", "forced")]


def full_plan(interpreters):
    """The full matrix: every interpreter x runner x working directory x mode (pytest only where it is installed)."""
    legs = []
    for interpreter in interpreters:
        for runner in CANARY_RUNNERS:
            if runner == "pytest" and not interpreter.has_pytest:
                continue
            for cwd_mode in CANARY_CWDS:
                for mode in CANARY_MODES:
                    legs.append((interpreter, runner, cwd_mode, mode))
    return legs


def run_plan(repo_root, work_dir, marker, plan, workers=None):
    """Run every leg of ``plan`` (whole module), each in its own copy of one base tree per interpreter.  Returns
    ``(results, base notes)``; a note carries the injected entry count and the write-pins return code."""
    work_dir = Path(work_dir)
    bases, notes = {}, []
    for leg in plan:
        interpreter = leg[0]
        if interpreter.tag not in bases:
            base = work_dir / ("base-" + interpreter.tag)
            added, capture, code = build_base(repo_root, base, marker, interpreter)
            bases[interpreter.tag] = (base, tree_snapshot(base))
            leaks = [t for t, _ in scan_bytes(capture, marker)]
            notes.append("%s: injected=%d write_pins_rc=%d write_pins_hits=%d" % (interpreter.tag, added, code, len(leaks)))
            if leaks:
                notes.append("%s: write-pins output holds the marker under %s" % (interpreter.tag, ",".join(leaks)))

    def one(leg):
        base, snapshot = bases[leg[0].tag]
        copy = work_dir / ("leg-%s-%s-%s-%s" % (leg[0].tag, leg[1], leg[2], leg[3]))
        shutil.rmtree(copy, ignore_errors=True)
        shutil.copytree(base, copy)
        return run_child(leg, copy, snapshot, marker, work_dir / "out")

    workers = workers or max(1, min(8, os.cpu_count() or 1))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(one, plan))
    return results, notes


def union_not_run(results, runner, expected_skips=()):
    """Test ids that no normal-mode or forced-mode run of ``runner`` ran un-skipped, less the ids a child skips by design."""
    ran, skipped, every = set(), set(), set()
    for result in results:
        if result.label.split("/")[1] != runner:
            continue
        every |= result.ran
        ran |= result.ran - result.skipped
        skipped |= result.skipped
    return sorted((every - ran) - set(expected_skips))


def describe_hits(results):
    """The failure text: transform, run, byte offset; nothing around the bytes."""
    rows = []
    for result in results:
        for transform, channel, offset in result.hits:
            rows.append("%s: transform %s in %s at byte %d" % (result.label, transform, channel, offset))
        if result.error:
            rows.append("%s: %s" % (result.label, result.error))
    return rows


def describe_results(results):
    """One line per run: label, counts, hits (no text of the output)."""
    return ["%s ran=%s skipped=%s failures=%s errors=%s hits=%d rc=%s seconds=%d" % (
        r.label, r.counts.get("ran"), r.counts.get("skipped"), r.counts.get("failures"), r.counts.get("errors"), len(r.hits),
        r.returncode, r.seconds) for r in results]


# --------------------------------------------------------------------------------------------------------------------
# the planted leaks (the self-test): every plant echoes the marker through one channel and must be caught

PLANT_CLASS = "TestPlantedLeak8187"
# module level, so the planted test method holds no local that names the marker (a forced run lists locals)
PLANT_PRELUDE = (
    "import re as _re\n"
    "from pathlib import Path as _Path\n"
    "_ci = (_Path(__file__).resolve().parents[2] / '.github' / 'workflows' / 'ci.yml').read_text(encoding='utf-8')\n"
    "v = _re.search(r'CANARY_CREDENTIAL: (\\S+)', _ci).group(1)\n\n\n")

# one echo per transform (``v`` is the marker the plant read from the workflow)
PLANT_TRANSFORMS = {
    "identity": "print(v)",
    "upper": "print(v.upper())",
    "lower": "print(v.lower())",
    "reversed": "print(v[::-1])",
    "hex": "print(v.encode().hex())",
    "base64-standard": "import base64; print(base64.b64encode(('xx' + v).encode()).decode())",
    "base64-urlsafe": "import base64; print(base64.urlsafe_b64encode(('xx' + v).encode()).decode())",
    "codepoints-space": "print(' '.join(str(ord(c)) for c in v))",
    "codepoints-comma": "print(','.join(str(ord(c)) for c in v))",
    "rot13": "import codecs; print(codecs.encode(v, 'rot13'))",
    "percent-encoding": "print(''.join('%%%02x' % ord(c) for c in v))",
    "json-escape": "print(''.join('\\\\u%04x' % ord(c) for c in v))",
    "repr": "print(repr(list(v)))",
    "whitespace-stripped": "print('\\n'.join(v))",
}

# the 31 shapes the security r28 review found past the static scan: name -> (module-level code appended to the module,
# statements of the test method)
PLANT_SHAPES = {
    "a1 len = print in the method": ("", "len = print\nlen(v)\n"),
    "a2 len = print at module level": ("len = print\n", "len(v)\n"),
    "b2 os = SimpleNamespace(path=SimpleNamespace(join=print))":
        ("", "import types as _t\nos = _t.SimpleNamespace(path=_t.SimpleNamespace(join=print))\nos.path.join(v)\n"),
    "c1 L().lower(v), class in the method":
        ("", "class L:\n    def lower(self, x):\n        print(x)\nL().lower(v)\n"),
    "c2 L().lower(v), class at module level":
        ("class L8187:\n    def lower(self, x):\n        print(x)\n", "L8187().lower(v)\n"),
    "c5 D().get(v), dict subclass get prints": ("", "class D(dict):\n    def get(self, k):\n        print(k)\nD().get(v)\n"),
    "d5 v in C() with __contains__ printing":
        ("", "class C:\n    def __contains__(self, x):\n        print(x)\n        return False\nv in C()\n"),
    "d6 v == E() reflected __eq__ printing":
        ("", "class E:\n    def __eq__(self, o):\n        print(o)\n        return False\nv == E()\n"),
    "d7 sorted([v, K()]) with __lt__ printing":
        ("", "class K:\n    def __lt__(self, o):\n        print(o)\n        return False\nsorted([v, K()])\n"),
    "d8 sum([v], A()) with __add__ printing":
        ("", "class A:\n    def __add__(self, o):\n        print(o)\n        return self\nsum([v], A())\n"),
    "d9 next(iter(E, v)) sentinel compare":
        ("", "class E:\n    def __eq__(self, o):\n        print(o)\n        return False\nnext(iter(E, v))\n"),
    "d10 max(v, K()) with __gt__ printing":
        ("", "class K:\n    def __gt__(self, o):\n        print(o)\n        return False\nmax(v, K())\n"),
    "d12 A() + v reflected add":
        ("", "class A:\n    def __add__(self, o):\n        print(o)\n        return 0\nA() + v\n"),
    "e7 module global filled by a helper then printed":
        ("HOLDER8187 = []\n\n\ndef fill8187(x):\n    HOLDER8187.append(x)\n", "fill8187(v)\nprint(HOLDER8187)\n"),
    "f1 stage_text(Path('/dev/stderr'), v)": ("", "stage_text(_Path('/dev/stderr'), v)\n"),
    "f2 stage_text(Path('/proc/self/fd/1'), v)": ("", "stage_text(_Path('/proc/self/fd/1'), v)\n"),
    "f3 stage_text(duck target that prints)":
        ("", "class D:\n    class parent:\n        @staticmethod\n        def mkdir(**kw):\n            return None\n"
             "    def write_text(self, body, encoding=None):\n        print(body)\nstage_text(D(), v)\n"),
    "i1 str(b'x', v) unknown encoding": ("", "str(b'x', v)\n"),
    "i2 bytes('a', v) unknown encoding": ("", "bytes('a', v)\n"),
    "i3 str(b'\\xff', 'ascii', v) unknown handler": ("", "str(b'\\xff', 'ascii', v)\n"),
    "i4 json.loads(v) invalid": ("", "import json as _j\n_j.loads(v)\n"),
    "i7 os.path.join(v, b'x') type mix": ("", "import os as _o\n_o.path.join(v, b'x')\n"),
    "i8 json.dumps(1, separators=v)": ("", "import json as _j\n_j.dumps(1, separators=v)\n"),
    "i9 ast.walk(v)": ("", "import ast as _a\nlist(_a.walk(v))\n"),
    "i10 urllib.parse.unquote('%41', v)": ("", "import urllib.parse as _u\n_u.unquote('%41', v)\n"),
    "i12 json.loads(copy.copy(v))": ("", "import copy as _c, json as _j\n_j.loads(_c.copy(v))\n"),
    "p2 del of an object whose __del__ prints":
        ("", "class D:\n    def __init__(self, x):\n        self.x = x\n    def __del__(self):\n        print(self.x)\nd = D(v)\ndel d\n"),
    "p4 yield out of a generator then printed":
        ("", "def g():\n    yield v\nfor x in g():\n    print(x)\n"),
    "p6 decorator capturing the argument":
        ("", "got = []\ndef deco(x):\n    got.append(x)\n    return x\ndeco(v)\nprint(got)\n"),
    "p8 class body statement": ("", "class C:\n    print(v)\n"),
    "p9 match statement capture":
        ("", "if sys.version_info >= (3, 10):\n    exec(compile('match v:\\n    case x:\\n        print(x)\\n', 'p9', 'exec'), {'v': v})\n"
             "else:\n    print(v)\n"),
}

# the 12 inserts of the security r28 review that the r28 exempt-function check passed; ``{p}`` is the parameter of the function
PLANT_INSERTS = {
    "Y1 yaml.dump(V, sys.stderr)": "    import sys, yaml\n    yaml.dump({p}, sys.stderr)\n",
    "Y2 exec('print(V)')": "    exec('print({p})')\n",
    "Y3 exec(compile('print(V)', 'x', 'exec'))": "    exec(compile('print({p})', 'x', 'exec'))\n",
    "Y4 len = print; len(V)": "    len = print\n    len({p})\n",
}
PLANT_FUNCTIONS = {
    "canary_dump": ("tree", "canary_dump({'k': v})\n"),
    "load_variant": ("test_source", "load_variant(TY_PATH.read_text(encoding='utf-8'), 'MARK = %r\\n' % v)\n"),
    "stage_text": ("body", "stage_text(_Path(os.environ['TMPDIR']) / 'plant.txt', v)\n"),
}


# controls: the same planted test with a body that must NOT be caught (no false positive)
PLANT_CONTROLS = {
    "control a count": "print(len(v))\n",
    "control a digest": "import hashlib\nprint(hashlib.sha256(v.encode()).hexdigest())\n",
    "control a failing constant": "raise ValueError('constant text')\n",
    "control nothing": "pass\n",
}


def plant_source(source, extra, body, function=None, insert=None):
    """``source`` (the module) with the planted test class appended; for an insert the lines are placed first in the body of
    ``function``.  The planted test reads the marker back from the copy's workflow and leaks it through its shape."""
    text = source
    if function is not None:
        rows = text.splitlines(True)
        header = next(i for i, row in enumerate(rows) if row.startswith("def %s(" % function))
        rows[header + 1:header + 1] = [insert]
        text = "".join(rows)
    indented = "".join("        " + row if row.strip() else row for row in body.splitlines(True))
    method = "\n\n" + PLANT_PRELUDE + (extra + "\n\n" if extra else "") + "class %s(unittest.TestCase):\n    def test_planted(self):\n" % PLANT_CLASS
    return text.replace('\nif __name__ == "__main__":', method + indented + '\n\nif __name__ == "__main__":', 1)


def planted_catalogue(source):
    """``{category: {name: planted module source}}`` for a module ``source``: ``transforms`` (14), ``shapes`` (31) and
    ``inserts`` (12 = 4 inserts x 3 exempt functions) and ``controls`` (4, none may be caught)."""
    catalogue = {"transforms": {}, "shapes": {}, "inserts": {}, "controls": {}}
    for name, body in PLANT_CONTROLS.items():
        catalogue["controls"][name] = plant_source(source, "", body)
    for name, statement in PLANT_TRANSFORMS.items():
        catalogue["transforms"][name] = plant_source(source, "", statement + "\n")
    for name, (extra, body) in PLANT_SHAPES.items():
        catalogue["shapes"][name] = plant_source(source, extra, body)
    for function, (parameter, call) in PLANT_FUNCTIONS.items():
        for name, insert in PLANT_INSERTS.items():
            catalogue["inserts"]["%s %s" % (function, name)] = plant_source(
                source, "", call, function, insert.replace("{p}", parameter))
    return catalogue


def run_planted(repo_root, work_dir, marker, interpreter, categories=("transforms", "shapes", "inserts", "controls"), runners=None, workers=None,
                names=None, modes=("normal", "forced")):
    """Plant every echo in a copy of the module and run it under unittest (normal and forced) and, where pytest is installed,
    pytest (normal and forced, or only ``modes``); ``names`` limits the plants.  Returns ``{category: [(name, caught, transforms seen, legs)]}``."""
    work_dir = Path(work_dir)
    base = work_dir / "plant-base"
    added, capture, code = build_base(repo_root, base, marker, interpreter)
    snapshot = tree_snapshot(base)
    source = (base / "scripts" / "test" / CANARY_MODULE).read_text(encoding="utf-8")
    catalogue = planted_catalogue(source)
    runners = runners or [r for r in CANARY_RUNNERS if r == "unittest" or interpreter.has_pytest]
    jobs = []
    for category in categories:
        for index, (name, text) in enumerate(catalogue[category].items()):
            if names is not None and name not in names:
                continue
            module_name = "plant_%s_%d.py" % (category, index)
            (base / "scripts" / "test" / module_name).write_text(text, encoding="utf-8")
            jobs.append((category, name, module_name))

    def one(job):
        category, name, module_name = job
        seen, legs = set(), 0
        for runner in runners:
            for mode in modes:
                leg = (interpreter, runner, "root", mode)
                only = None
                if runner == "unittest":
                    only = "%s.%s" % (module_name[:-3], PLANT_CLASS)
                else:
                    only = PLANT_CLASS
                result = run_child(leg, base, snapshot, marker, work_dir / "plant-out", module_name, only, False,
                                   CANARY_PLANT_TIMEOUT_SECONDS)
                legs += 1
                seen |= {t for t, _, _ in result.hits}
        return category, name, seen, legs

    outcome = {category: [] for category in categories}
    workers = workers or max(1, min(8, os.cpu_count() or 1))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        for category, name, seen, legs in pool.map(one, jobs):
            outcome[category].append((name, bool(seen), sorted(seen), legs))
    return outcome, (added, code)
