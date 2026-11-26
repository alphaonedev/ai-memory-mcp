#!/usr/bin/env python3
"""Invariants of the per-binary Postgres isolation lane (#6383 / #6386, #9592).

Replaces the r1 shell Section G of scripts/test/test-ci-workflow-invariants.sh
(review r1 L1). Checks, each with an id that names its review finding:

G1-opt-in              AI_MEMORY_TEST_PG_ISOLATE is set at exactly ONE site in
                       every workflow and action under .github: the step env
                       key of the "Serial shard isolated binaries" step of job
                       ``check``, value ``"1"``, guarded to linux-fed
                       enterprise-fed and away from fork pull requests, running
                       pg_isolate_serial_step.py run inside the host semaphore
                       (3-agent vote (71472661) decision A, I-1 / I-3; M4). Any
                       second site, any other value form, any job, workflow,
                       matrix or ``with:`` key, any run-script assignment other
                       than ``=0``, any expression-valued ``env:`` mapping, any
                       unparseable workflow, and any script under scripts/ that
                       names the flag within FLAG_ENV_WINDOW lines of
                       GITHUB_ENV is red (#9592 C-L5).
G2-no-ci-sweep         neither ci.yml nor the step entry runs the admin-only
                       cross-run sweep. H2.
G3-no-url-argv         no wrapper call in ci.yml or the entry passes ``--url``. L3.
G4-setup-teardown      ci.yml runs the entry (``run``) and its always()
                       ``cleanup``; the entry runs wrapper setup and teardown.
G5-prebuild-selection  the entry prebuilds (``--no-run``) only the selection. H1.
G6-watchdog            the entry keeps the #1492 watchdog (``--kill-after=60``).
G7-log-upload          an ``if: always()`` upload step ships the per-binary logs,
                       and an always() step redacts them before it. M3, #9592 SD.
G8-kill-switch         "Run tests" AND the isolated step each set the exact env
                       line ``CI_PG_ISOLATE_OFF: ${{ vars.CI_PG_ISOLATE_OFF }}``.
                       #9592 C-M1.
G9-template-guard      the entry fails closed without the template. M1/M6.
G10-deferral           "Run tests" decides the kill switch, the deferral and the
                       mode with the pinned lines (DEFER_PINS), on the leg of the
                       isolated step's if: (DEFER_NODE / DEFER_TIER). #9592 C-M1.
G11-cleanup            the always() Cleanup step runs the entry's ``cleanup``
                       before its first exit and every exit is ``exit "$iso_rc"``.
                       #9592 C-M1 / SB.
G12-continue-on-error  no continue-on-error on job ``check`` or on the steps of
                       the handshake (Run tests, isolated, Redact, Cleanup).
G13-fork-guard         the isolated step never runs on a fork pull request. SG.
G14-host-semaphore     the isolated step runs inside the #7914 host semaphore with
                       the slots, wait, node and tier of "Run tests". C-M2.
run-help               ``pg_isolated_binary.py run --help`` EXECUTES and
                       lists its flags (C1, L2: not a docstring grep).
source                 neither the wrapper nor the Rust helper drops WITH
                       FORCE, and the wrapper checks pg_stat_activity.

Usage: check_pg_isolate_invariants.py --root REPO [--ci-yml PATH]
Exit 0 and ``ok`` lines when every check holds, 1 otherwise.
"""
import argparse
import bisect
import importlib.util
import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

FLAG = 'AI_MEMORY_TEST_PG_ISOLATE'
WRAPPER = 'pg_isolated_binary.py'
ENTRY = 'pg_isolate_serial_step.py'
CI_REL = '.github/workflows/ci.yml'
ALLOWED_JOB = 'check'
ALLOWED_STEP = 'Serial shard isolated binaries (linux-fed enterprise-fed, issue 9592)'
DEFER_NODE = 'linux-fed'
DEFER_TIER = 'enterprise-fed'
FORK_GUARD = ("(github.event_name != 'pull_request' || "
              "github.event.pull_request.head.repo.full_name == github.repository)")
ALLOWED_IF = ("${{ !cancelled() && steps.run-tests.outcome != 'skipped' && "
              "needs.classify.outputs.cargo_skip != 'true' && matrix.node == '%s' && "
              "matrix.tier == '%s' && %s }}" % (DEFER_NODE, DEFER_TIER, FORK_GUARD))
ENTRY_RUN = 'python3 scripts/ci/%s run' % ENTRY
ALLOWED_RUN = ('python3 -I scripts/ci/host_semaphore.py --name linux-fed-tests --slots "$HOST_SEMAPHORE_SLOTS" '
               '--max-wait-secs "$HOST_SEMAPHORE_MAX_WAIT_SECS" --label "${CI_NODE}/${TIER}/iso" -- ' + ENTRY_RUN)
RUN_TESTS_STEP = 'Run tests (impact-aware)'
CLEANUP_STEP = 'Cleanup enterprise-fed ephemeral db'
REDACT_STEP = 'Redact isolated-lane per-binary logs (issue 9592)'
KILL_KEY = 'CI_PG_ISOLATE_OFF'
KILL_VALUE = '${{ vars.CI_PG_ISOLATE_OFF }}'
# The lines of the "Run tests" run script that decide the kill switch, the
# deferral and the mode (G10). Pins 1 and 2 name the leg of ALLOWED_IF.
DEFER_PINS = (
    'PG_ISO_KILL="$(python3 scripts/ci/%s killswitch)"' % ENTRY,
    'if [ "${CI_NODE:-}" = "%s" ] && [ "${TIER:-}" = "%s" ] && [ "$PG_ISO_KILL" = "off" ]; then'
    % (DEFER_NODE, DEFER_TIER),
    'if [ "${CI_NODE:-}" = "%s" ] && [ "${TIER:-}" = "%s" ] && [ "$PG_ISO_KILL" = "on" ]; then'
    % (DEFER_NODE, DEFER_TIER),
    'echo "$PG_ISO_MODE" > "$PG_ISO_MODE_FILE"',
    'if [ "$PG_ISO_DEFER" = "1" ]; then',
    'echo deferred > "$PG_ISO_MODE_FILE"',
)
CLEANUP_CALL = 'python3 scripts/ci/%s cleanup || iso_rc=$?' % ENTRY
CLEANUP_EXIT = 'exit "$iso_rc"'
ALWAYS_PREFIX = 'always() && '
REDACT_RUN = 'python3 scripts/ci/%s redact-logs' % ENTRY
SEMAPHORE_ENV = ('HOST_SEMAPHORE_SLOTS', 'HOST_SEMAPHORE_MAX_WAIT_SECS', 'CI_NODE', 'TIER')
NO_CONTINUE_STEPS = (RUN_TESTS_STEP, ALLOWED_STEP, REDACT_STEP, CLEANUP_STEP)
FLAG_ENV_WINDOW = 3
SCRIPTS_DIR = 'scripts'
SCRIPT_SUFFIXES = ('.py', '.sh', '.bash', '.pl', '.rb', '.js', '.mjs', '.ts')
SCRIPT_EXCLUDED_DIR = 'tests'
GATE_REL = 'scripts/ci/check_pg_isolate_invariants.py'
ALLOWED_RAW = '"1"'
ENTRY_CALLS = (ENTRY + ' run', ENTRY + ' cleanup')
LOG_PATH = 'ci-shard/iso-logs'
RUN_FLAGS = ('--url', '--run-id', '--template', '--log-dir', '--targets-file', '--jobs',
             '--residual-file', '--test-arg')
FORCE = 'WITH (FORCE)'
YAML_SUFFIXES = ('.yml', '.yaml')
TAINT_BOUNDARY = Path(__file__).resolve().parent / 'taint_boundary.py'

_ASSIGN_RE = re.compile(r'\b%s=(?!0\b)' % FLAG)
_RAW_KEY_RE = re.compile(r'^\s*%s\s*:\s*(.*?)\s*$' % FLAG)
_STEP_RE = re.compile(r'^\s*- name:', re.M)
_FLAG_TOKEN_RE = re.compile(r'\b%s\b' % FLAG)
_GITHUB_ENV_RE = re.compile(r'\bGITHUB_ENV\b')
_EXIT_RE = re.compile(r'(?:^|[;&|]\s*|\bthen\s+|\belse\s+|\bdo\s+)(exit\b[^;&|#]*)')
_QUOTED = '[\'"]%s[\'"]'

Failure = Tuple[str, str]


def _code_lines(text: str) -> List[str]:
    return [ln for ln in text.splitlines() if not ln.lstrip().startswith('#')]


def _steps(text: str) -> List[str]:
    starts = [m.start() for m in _STEP_RE.finditer(text)] + [len(text)]
    return [text[a:b] for a, b in zip(starts, starts[1:])]


def _parse_yaml(text: str, label: str) -> object:
    """The repository's stdlib YAML subset (taint_boundary.py): an unparseable workflow is a failure."""
    spec = importlib.util.spec_from_file_location('taint_boundary_pg_isolate', TAINT_BOUNDARY)
    if spec is None or spec.loader is None:
        raise ImportError('cannot load %s' % TAINT_BOUNDARY.name)
    if 'taint_boundary_pg_isolate' not in sys.modules:
        module = importlib.util.module_from_spec(spec)
        sys.modules['taint_boundary_pg_isolate'] = module
        spec.loader.exec_module(module)
    return sys.modules['taint_boundary_pg_isolate'].parse_yaml(text, label)


def workflow_files(repo: Path) -> List[str]:
    """Every workflow and action file under .github, as repository-relative paths."""
    root = repo / '.github'
    return sorted(p.relative_to(repo).as_posix() for p in root.rglob('*')
                  if p.is_file() and p.suffix in YAML_SUFFIXES)


def _flag_keys(node: object, path: str):
    """Every mapping path under ``node`` that holds the flag as a key."""
    if isinstance(node, dict):
        if FLAG in node:
            yield path
        for key, value in node.items():
            yield from _flag_keys(value, '%s/%s' % (path, key) if path else str(key))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from _flag_keys(value, '%s/%d' % (path, index))


def _env_expressions(node: object, path: str):
    """Every mapping path whose ``env`` value is not a mapping (an expression can carry any key)."""
    if isinstance(node, dict):
        for key, value in node.items():
            sub = '%s/%s' % (path, key) if path else str(key)
            if key == 'env' and not isinstance(value, dict) and value is not None:
                yield sub
            else:
                yield from _env_expressions(value, sub)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from _env_expressions(value, '%s/%d' % (path, index))


def _expression_env_reasons(doc: object, rel: str) -> List[str]:
    return ['an expression-valued env: in %s at %s' % (rel, path) for path in _env_expressions(doc, '')]


def script_files(repo: Path) -> Dict[str, str]:
    """Every script under scripts/ (by suffix) as ``{relative path: text}``."""
    root = repo / SCRIPTS_DIR
    out: Dict[str, str] = {}
    for path in sorted(root.rglob('*')):
        if path.is_file() and path.suffix in SCRIPT_SUFFIXES:
            out[path.relative_to(repo).as_posix()] = path.read_text(encoding='utf-8', errors='replace')
    return out


def _script_excluded(rel: str) -> bool:
    return rel == GATE_REL or SCRIPT_EXCLUDED_DIR in rel.split('/')[:-1]


def script_flag_reasons(files: Dict[str, str]) -> List[str]:
    """C-L5: a script that names the flag within FLAG_ENV_WINDOW lines of GITHUB_ENV (linear per file)."""
    out: List[str] = []
    for rel in sorted(files):
        if _script_excluded(rel):
            continue
        flag_lines: List[int] = []
        env_lines: List[int] = []
        for number, line in enumerate(files[rel].splitlines(), 1):
            if FLAG in line and _FLAG_TOKEN_RE.search(line):
                flag_lines.append(number)
            if 'GITHUB_ENV' in line and _GITHUB_ENV_RE.search(line):
                env_lines.append(number)
        for number in flag_lines:
            at = bisect.bisect_left(env_lines, number - FLAG_ENV_WINDOW)
            if at < len(env_lines) and env_lines[at] <= number + FLAG_ENV_WINDOW:
                out.append('%s within %d lines of GITHUB_ENV: %s:%d' % (FLAG, FLAG_ENV_WINDOW, rel, number))
    return out


def _allowed_block(text: str) -> List[str]:
    """The raw lines of the allowed step (its ``- name:`` line to the next sibling)."""
    lines = text.splitlines()
    for at, line in enumerate(lines):
        if line.strip() == '- name: ' + ALLOWED_STEP:
            indent = len(line) - len(line.lstrip())
            block = [line]
            for nxt in lines[at + 1:]:
                if nxt.strip() and len(nxt) - len(nxt.lstrip()) <= indent:
                    break
                block.append(nxt)
            return block
    return []


def _ci_reasons(text: str) -> List[str]:
    try:
        doc = _parse_yaml(text, CI_REL)
    except Exception as exc:  # any parser failure is red, never clean
        return ['unparseable workflow %s: %s' % (CI_REL, exc)]
    if not isinstance(doc, dict):
        return ['unparseable workflow %s: not a mapping' % CI_REL]
    out: List[str] = _expression_env_reasons(doc, CI_REL)
    sites: List[Tuple[str, str, dict]] = []
    known = set()
    if isinstance(doc.get('env'), dict) and FLAG in doc['env']:
        out.append('workflow-level env sets %s in %s' % (FLAG, CI_REL))
        known.add('env')
    jobs = doc.get('jobs') if isinstance(doc.get('jobs'), dict) else {}
    for jid, job in jobs.items():
        if not isinstance(job, dict):
            continue
        if isinstance(job.get('env'), dict) and FLAG in job['env']:
            out.append('job-level env sets %s in %s job %s' % (FLAG, CI_REL, jid))
            known.add('jobs/%s/env' % jid)
        matrix = list(_flag_keys(job.get('strategy'), 'jobs/%s/strategy' % jid))
        if matrix:
            out.append('matrix sets %s in %s job %s' % (FLAG, CI_REL, jid))
            known.update(matrix)
        steps = job.get('steps') if isinstance(job.get('steps'), list) else []
        for index, step in enumerate(steps):
            if not isinstance(step, dict):
                continue
            name = str(step.get('name'))
            if isinstance(step.get('env'), dict) and FLAG in step['env']:
                sites.append((str(jid), name, step))
                known.add('jobs/%s/steps/%d/env' % (jid, index))
            if isinstance(step.get('run'), str) and _ASSIGN_RE.search(step['run']):
                out.append("a run: script assigns %s in %s job %s step '%s'" % (FLAG, CI_REL, jid, name))
    out += ['%s is not set through a step env key in %s at %s' % (FLAG, CI_REL, path)
            for path in _flag_keys(doc, '') if path not in known]
    allowed = 0
    for jid, name, step in sites:
        if jid != ALLOWED_JOB:
            out.append('step env sets %s in job %s (allowed: %s)' % (FLAG, jid, ALLOWED_JOB))
        elif name != ALLOWED_STEP:
            out.append('step %r sets %s (allowed: %r)' % (name, FLAG, ALLOWED_STEP))
        else:
            allowed += 1
            out += _allowed_step_reasons(text, step)
    if len(sites) > 1:
        out.append('%s is set at %d sites (allowed: exactly one)' % (FLAG, len(sites)))
    if allowed == 0:
        out.append('no step sets %s (allowed: exactly one, %r)' % (FLAG, ALLOWED_STEP))
    return out


def _allowed_step_reasons(text: str, step: dict) -> List[str]:
    out = []
    if step.get('if') != ALLOWED_IF:
        out.append('the allowed step runs on another leg: if is %r' % step.get('if'))
    if str(step.get('run', '')).strip() != ALLOWED_RUN:
        out.append('the allowed step does not run %r' % ALLOWED_RUN)
    raws = [m.group(1) for m in map(_RAW_KEY_RE.match, _allowed_block(text)) if m]
    bad = [raw for raw in raws if raw != ALLOWED_RAW]
    if bad or len(raws) != 1:
        out.append('the allowed step sets %s to %s (allowed: %s)' % (FLAG, (bad or raws or ['?'])[0], ALLOWED_RAW))
    return out


def g1_reasons(files: Dict[str, str]) -> List[str]:
    """I-3: every reason the one-site rule fails over ``{relative path: text}``; empty when it holds."""
    out: List[str] = []
    for rel in sorted(files):
        text = files[rel]
        if rel == CI_REL:
            out += _ci_reasons(text)
            continue
        try:
            doc = _parse_yaml(text, rel)
        except Exception as exc:  # any parser failure is red, never clean
            out.append('unparseable workflow %s: %s' % (rel, exc))
            continue
        out += _expression_env_reasons(doc, rel)
        if any(FLAG in ln for ln in _code_lines(text)):
            out.append('%s outside the allowed step: %s' % (FLAG, rel))
    return out


def _check_job(ci_text: str) -> Tuple[Optional[dict], List[dict]]:
    """Job ``check`` of ci.yml and its step mappings; ``(None, [])`` when unparseable (G1 says why)."""
    try:
        doc = _parse_yaml(ci_text, CI_REL)
    except Exception:  # G1 already reports the parser failure
        return None, []
    jobs = doc.get('jobs') if isinstance(doc, dict) else None
    job = jobs.get(ALLOWED_JOB) if isinstance(jobs, dict) else None
    if not isinstance(job, dict):
        return None, []
    steps = job.get('steps') if isinstance(job.get('steps'), list) else []
    return job, [step for step in steps if isinstance(step, dict)]


def _named(steps: List[dict], name: str) -> Tuple[int, Optional[dict]]:
    for index, step in enumerate(steps):
        if step.get('name') == name:
            return index, step
    return -1, None


def _run_lines(step: Optional[dict]) -> List[str]:
    run = step.get('run') if step else None
    return [ln.strip() for ln in str(run or '').splitlines() if ln.strip() and not ln.lstrip().startswith('#')]


def _env(step: Optional[dict]) -> dict:
    env = step.get('env') if step else None
    return env if isinstance(env, dict) else {}


def wiring_failures(ci_text: str) -> List[Failure]:
    """G7 redact, G8, G10-G14: the halves of the #9592 handshake agree step by step."""
    job, steps = _check_job(ci_text)
    if job is None:
        return [('G10-deferral', 'ci.yml has no parseable job %s' % ALLOWED_JOB)]
    out: List[Failure] = []
    _, run_tests = _named(steps, RUN_TESTS_STEP)
    _, iso = _named(steps, ALLOWED_STEP)
    _, redact = _named(steps, REDACT_STEP)
    _, cleanup = _named(steps, CLEANUP_STEP)
    for name, step in ((RUN_TESTS_STEP, run_tests), (ALLOWED_STEP, iso), (REDACT_STEP, redact),
                       (CLEANUP_STEP, cleanup)):
        if step is None:
            out.append(('G10-deferral', 'job %s has no step %r' % (ALLOWED_JOB, name)))
    for name, step in ((RUN_TESTS_STEP, run_tests), (ALLOWED_STEP, iso)):
        if step is not None and _env(step).get(KILL_KEY) != KILL_VALUE:
            out.append(('G8-kill-switch', 'step %r does not set %s: %s' % (name, KILL_KEY, KILL_VALUE)))
    lines = set(_run_lines(run_tests))
    out += [('G10-deferral', 'Run tests lost the deferral pin %r' % pin) for pin in DEFER_PINS if pin not in lines]
    out += _cleanup_failures(cleanup)
    if 'continue-on-error' in job:
        out.append(('G12-continue-on-error', 'continue-on-error on job %s' % ALLOWED_JOB))
    for step in steps:
        if step.get('name') in NO_CONTINUE_STEPS and 'continue-on-error' in step:
            out.append(('G12-continue-on-error', 'continue-on-error on step %r' % step.get('name')))
    if iso is not None:
        if FORK_GUARD not in str(iso.get('if', '')):
            out.append(('G13-fork-guard', 'the isolated step has no fork guard %r' % FORK_GUARD))
        if str(iso.get('run', '')).strip() != ALLOWED_RUN:
            out.append(('G14-host-semaphore', 'the isolated step does not run %r' % ALLOWED_RUN))
        for key in SEMAPHORE_ENV:
            value = _env(iso).get(key)
            if value is None or value != _env(run_tests).get(key):
                out.append(('G14-host-semaphore', 'the isolated step env %s differs from Run tests' % key))
    upload_at = next((i for i, s in enumerate(steps)
                      if 'actions/upload-artifact@' in str(s.get('uses', '')) and LOG_PATH in str(s)), len(steps))
    redacts = [i for i, s in enumerate(steps) if str(s.get('run', '')).strip() == REDACT_RUN
               and str(s.get('if', '')).startswith(ALWAYS_PREFIX) and i < upload_at]
    if not redacts:
        out.append(('G7-log-upload', 'no always() step runs %r before the %s upload' % (REDACT_RUN, LOG_PATH)))
    return out


def _cleanup_failures(cleanup: Optional[dict]) -> List[Failure]:
    if cleanup is None:
        return []
    out: List[Failure] = []
    if not str(cleanup.get('if', '')).startswith(ALWAYS_PREFIX):
        out.append(('G11-cleanup', 'the Cleanup step is not always()'))
    lines = _run_lines(cleanup)
    exits = [(at, m.group(1).strip()) for at, ln in enumerate(lines) for m in _EXIT_RE.finditer(ln)]
    out += [('G11-cleanup', 'the Cleanup step exits with %r (allowed: %r)' % (cmd, CLEANUP_EXIT))
            for _, cmd in exits if cmd != CLEANUP_EXIT]
    first_exit = exits[0][0] if exits else len(lines)
    if not any(ln == CLEANUP_CALL for ln in lines[:first_exit]):
        out.append(('G11-cleanup', 'the Cleanup step does not run %r before its first exit' % CLEANUP_CALL))
    return out


def static_failures(ci_text: str, repo: Path) -> List[Failure]:
    """Every failed ci.yml invariant as ``(id, message)``; empty when all hold."""
    files = {rel: (repo / rel).read_text(encoding='utf-8') for rel in workflow_files(repo) if rel != CI_REL}
    files[CI_REL] = ci_text
    out: List[Failure] = [('G1-opt-in', reason) for reason in g1_reasons(files)]
    out += [('G1-opt-in', reason) for reason in script_flag_reasons(script_files(repo))]
    code = _code_lines(ci_text)
    calls = [ln for ln in code if WRAPPER in ln]
    if any(WRAPPER + ' sweep' in ln for ln in calls):
        out.append(('G2-no-ci-sweep', 'ci.yml runs the admin-only cross-run sweep'))
    if any(re.search(r'(^|\s)--url(\s|=|$)', ln) for ln in calls):
        out.append(('G3-no-url-argv', 'a %s call in ci.yml passes the URL in argv' % WRAPPER))
    if not all(any(call in ln for ln in code) for call in ENTRY_CALLS):
        out.append(('G4-setup-teardown', 'ci.yml must run both %s' % ' and '.join(ENTRY_CALLS)))
    uploads = [s for s in _steps(ci_text)
               if 'actions/upload-artifact@' in s and LOG_PATH in s and 'always()' in s]
    if not uploads:
        out.append(('G7-log-upload', 'no if: always() upload step for %s' % LOG_PATH))
    out += wiring_failures(ci_text)
    return out


def entry_failures(text: str) -> List[Failure]:
    """G2-G6 / G9 on the serial shard step entry (it, not ci.yml, calls the wrapper since #9592)."""
    out: List[Failure] = []
    if re.search(_QUOTED % 'sweep', text):
        out.append(('G2-no-ci-sweep', 'the step entry runs the admin-only cross-run sweep'))
    if re.search(_QUOTED % '--url', text):
        out.append(('G3-no-url-argv', 'the step entry passes the URL in argv'))
    if not (re.search(_QUOTED % 'setup', text) and re.search(_QUOTED % 'teardown', text)):
        out.append(('G4-setup-teardown', 'the step entry must run both wrapper setup and teardown'))
    if not re.search(_QUOTED % '--no-run', text):
        out.append(('G5-prebuild-selection', 'the step entry must prebuild the selection with --no-run'))
    if not re.search(_QUOTED % '--kill-after=60', text):
        out.append(('G6-watchdog', 'the step entry lost its --kill-after=60 watchdog'))
    if 'setup emitted no' not in text:
        out.append(('G9-template-guard', 'the step entry does not fail closed without the template'))
    return out


def run_help_failure(repo: Path) -> Optional[str]:
    """Execute ``run --help``; ``None`` when it works and lists every flag."""
    wrapper = repo / 'scripts' / 'test' / WRAPPER
    try:
        done = subprocess.run([sys.executable, str(wrapper), 'run', '--help'],
                              capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 'could not execute %s run --help: %s' % (WRAPPER, exc)
    if done.returncode != 0:
        return '%s run --help exited %d: %s' % (WRAPPER, done.returncode, done.stderr.strip()[-300:])
    missing = [flag for flag in RUN_FLAGS if flag not in done.stdout]
    if missing:
        return '%s run --help does not list %s' % (WRAPPER, ', '.join(missing))
    return None


def source_failure(kind: str, text: str) -> Optional[str]:
    """Source rules for ``wrapper`` (Python) or ``helper`` (Rust)."""
    if FORCE in text:
        return '%s drops a database %s' % (kind, FORCE)
    if kind == 'wrapper':
        if 'pg_stat_activity' not in text:
            return 'the wrapper no longer checks pg_stat_activity (budget / idle guard)'
        if 'shell=True' in text:
            return 'the wrapper uses shell=True'
    elif kind != 'helper':
        return 'unknown source kind %r' % kind
    return None


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split('\n', 1)[0])
    parser.add_argument('--root', required=True, help='repository root')
    parser.add_argument('--ci-yml', help='workflow to check (default: <root>/.github/workflows/ci.yml)')
    args = parser.parse_args(argv)
    root = Path(args.root)
    ci_yml = Path(args.ci_yml) if args.ci_yml else root / '.github' / 'workflows' / 'ci.yml'
    failures = static_failures(ci_yml.read_text(encoding='utf-8'), root)
    failures += entry_failures((root / 'scripts' / 'ci' / ENTRY).read_text(encoding='utf-8'))
    help_failure = run_help_failure(root)
    if help_failure:
        failures.append(('run-help', help_failure))
    for kind, rel in (('wrapper', 'scripts/test/' + WRAPPER), ('helper', 'tests/common/pg_isolate.rs')):
        found = source_failure(kind, (root / rel).read_text(encoding='utf-8'))
        if found:
            failures.append(('source', found))
    for cid, msg in failures:
        print('FAIL %s: %s' % (cid, msg))
    if failures:
        return 1
    print('ok: pg-isolation invariants hold (G1-G14, run-help, source)')
    return 0


if __name__ == '__main__':
    sys.exit(main())
