#!/usr/bin/env python3
"""Invariants of the per-binary Postgres isolation lane (#6383 / #6386, #9592).

Replaces the r1 shell Section G of scripts/test/test-ci-workflow-invariants.sh
(review r1 L1). Checks, each with an id that names its review finding:

G1-opt-in              AI_MEMORY_TEST_PG_ISOLATE is set at exactly ONE site in
                       every workflow and action under .github: the step env
                       key of the "Serial shard isolated binaries" step of job
                       ``check``, value ``"1"``, guarded to linux-fed
                       enterprise-fed, running pg_isolate_serial_step.py run
                       (3-agent vote (71472661) decision A, I-1 / I-3; M4). Any
                       second site, any other value form, any job, workflow,
                       matrix or ``with:`` key, any run-script assignment other
                       than ``=0`` and any unparseable workflow is red.
G2-no-ci-sweep         neither ci.yml nor the step entry runs the admin-only
                       cross-run sweep. H2.
G3-no-url-argv         no wrapper call in ci.yml or the entry passes ``--url``. L3.
G4-setup-teardown      ci.yml runs the entry (``run``) and its always()
                       ``cleanup``; the entry runs wrapper setup and teardown.
G5-prebuild-selection  the entry prebuilds (``--no-run``) only the selection. H1.
G6-watchdog            the entry keeps the #1492 watchdog (``--kill-after=60``).
G7-log-upload          an ``if: always()`` upload step ships the per-binary logs. M3.
G8-kill-switch         the CI_PG_ISOLATE_OFF repo variable is wired.
G9-template-guard      the entry fails closed without the template. M1/M6.
run-help               ``pg_isolated_binary.py run --help`` EXECUTES and
                       lists its flags (C1, L2: not a docstring grep).
source                 neither the wrapper nor the Rust helper drops WITH
                       FORCE, and the wrapper checks pg_stat_activity.

Usage: check_pg_isolate_invariants.py --root REPO [--ci-yml PATH]
Exit 0 and ``ok`` lines when every check holds, 1 otherwise.
"""
import argparse
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
ALLOWED_IF = ("${{ !cancelled() && steps.run-tests.outcome != 'skipped' && "
              "needs.classify.outputs.cargo_skip != 'true' && matrix.node == 'linux-fed' && "
              "matrix.tier == 'enterprise-fed' }}")
ALLOWED_RUN = 'python3 scripts/ci/%s run' % ENTRY
ALLOWED_RAW = '"1"'
ENTRY_CALLS = (ENTRY + ' run', ENTRY + ' cleanup')
LOG_PATH = 'ci-shard/iso-logs'
KILL_VAR = 'vars.CI_PG_ISOLATE_OFF'
RUN_FLAGS = ('--url', '--run-id', '--template', '--log-dir', '--targets-file', '--jobs',
             '--residual-file', '--test-arg')
FORCE = 'WITH (FORCE)'
YAML_SUFFIXES = ('.yml', '.yaml')
TAINT_BOUNDARY = Path(__file__).resolve().parent / 'taint_boundary.py'

_ASSIGN_RE = re.compile(r'\b%s=(?!0\b)' % FLAG)
_RAW_KEY_RE = re.compile(r'^\s*%s\s*:\s*(.*?)\s*$' % FLAG)
_STEP_RE = re.compile(r'^\s*- name:', re.M)
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
    out: List[str] = []
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
            _parse_yaml(text, rel)
        except Exception as exc:  # any parser failure is red, never clean
            out.append('unparseable workflow %s: %s' % (rel, exc))
            continue
        if any(FLAG in ln for ln in _code_lines(text)):
            out.append('%s outside the allowed step: %s' % (FLAG, rel))
    return out


def static_failures(ci_text: str, repo: Path) -> List[Failure]:
    """Every failed ci.yml invariant as ``(id, message)``; empty when all hold."""
    files = {rel: (repo / rel).read_text(encoding='utf-8') for rel in workflow_files(repo) if rel != CI_REL}
    files[CI_REL] = ci_text
    out: List[Failure] = [('G1-opt-in', reason) for reason in g1_reasons(files)]
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
    if KILL_VAR not in ci_text:
        out.append(('G8-kill-switch', 'the %s kill switch is not wired' % KILL_VAR))
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
    print('ok: pg-isolation invariants hold (G1-G9, run-help, source)')
    return 0


if __name__ == '__main__':
    sys.exit(main())
