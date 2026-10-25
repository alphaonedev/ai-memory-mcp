#!/usr/bin/env python3
"""Invariants of the per-binary Postgres isolation lane (#6383 / #6386).

Replaces the r1 shell Section G of scripts/test/test-ci-workflow-invariants.sh
(review r1 L1). Checks, each with an id that names its review finding:

G1-default-on          AI_MEMORY_TEST_PG_ISOLATE is 1 ONLY through the
                       enterprise-fed tier expression in the ``check`` job env
                       (both fed legs), every other assignment is 0, and the
                       CI_PG_ISOLATE_OFF kill-switch branch still forces 0.
                       Decision 919f1943, 3-agent vote (6def5ab6), 2026-10-24,
                       supersedes the r1 M4 opt-in rule (vote 4d3ea1c5).
G2-no-ci-sweep         ci.yml never runs the admin-only cross-run sweep. H2.
G3-no-url-argv         no wrapper call in ci.yml passes ``--url``. L3.
G4-setup-teardown      ci.yml runs both ``setup`` and ``teardown``.
G5-prebuild-selection  the isolated lane prebuilds only its selected targets. H1.
G6-watchdog            the isolated lane keeps the #1492 watchdog line.
G7-log-upload          an ``if: always()`` upload step ships the per-binary logs. M3.
G8-kill-switch         the CI_PG_ISOLATE_OFF repo variable is wired.
G9-template-guard      the lane fails closed without the template. M1/M6.
run-help               ``pg_isolated_binary.py run --help`` EXECUTES and
                       lists its flags (C1, L2: not a docstring grep).
source                 neither the wrapper nor the Rust helper drops WITH
                       FORCE, and the wrapper checks pg_stat_activity.

Scanner limits: the G1 line scanner matches the flag key as text on one code line, so two forms
are out of its scope and are covered by the run-step guard check instead: a name built by
``printf '%s=1' <name>`` and the YAML explicit ``? key`` form.

Usage: check_pg_isolate_invariants.py --root REPO [--ci-yml PATH]
Exit 0 and ``ok`` lines when every check holds, 1 otherwise.
"""
import argparse
import re
import subprocess
import sys
from pathlib import Path
from typing import List, Optional, Tuple

FLAG = 'AI_MEMORY_TEST_PG_ISOLATE'
WRAPPER = 'pg_isolated_binary.py'
PREBUILD = 'cargo test --no-run "$@" "${sel[@]}"'
WATCHDOG = ('"$TIMEOUT_BIN" --signal=TERM --kill-after=60 "$WATCHDOG_SECS" '
            'python3 scripts/test/pg_isolated_binary.py run')
LOG_PATH = 'ci-shard/iso-logs'
KILL_VAR = 'vars.CI_PG_ISOLATE_OFF'
TEMPLATE_GUARD = '${AI_MEMORY_TEST_PG_TEMPLATE:-}'
RUN_FLAGS = ('--url', '--run-id', '--template', '--log-dir', '--targets-file', '--jobs',
             '--residual-file', '--test-arg')
FORCE = 'WITH (FORCE)'

FED_EXPR = "${{ matrix.tier == 'enterprise-fed' && '1' || '0' }}"
FED_LEGS = ('leg: linux-fed,enterprise-fed', 'leg: macos-fed,enterprise-fed')
KILL_BRANCH_RE = re.compile(r'elif \[ "\$\{CI_PG_ISOLATE_OFF:-\}" = "1" \]; then\n\s+'
                            r'echo "%s=0" >> "\$GITHUB_ENV"' % FLAG)

RUN_GUARD = ('if [ "${AI_MEMORY_TEST_PG_ISOLATE:-0}" = "1" ] && [ "${CI_PG_ISOLATE_OFF:-}" != "1" ] '
             '&& [ "${TIER:-}" = "enterprise-fed" ]; then')

# The flag name followed by ``:`` (YAML, block or flow) or ``=`` (shell), searched on a code line
# with quotes removed so a quoted key or a quote-split name cannot hide it. ``:-`` ``:=`` ``:+``
# ``:?`` are shell parameter expansions (reads), not assignments.
_FLAG_KEY_RE = re.compile(r'%s(?:\s*:(?![-=+?])|=(?!=))' % FLAG)
# A literal 0 only: followed by end of line, whitespace or one of , } # ; & | (so ``0${{ x }}`` is not 0).
_ZERO_RE = re.compile(r'\s*0(?=$|[\s,}#;&|])')
_JOB_RE = re.compile(r'^  [A-Za-z0-9_-]+:\s*$', re.M)
_STEP_RE = re.compile(r'^\s*- name:', re.M)

Failure = Tuple[str, str]


def _code_lines(text: str) -> List[str]:
    return [ln for ln in text.splitlines() if not ln.lstrip().startswith('#')]


def _steps(text: str) -> List[str]:
    starts = [m.start() for m in _STEP_RE.finditer(text)] + [len(text)]
    return [text[a:b] for a, b in zip(starts, starts[1:])]


def _unquote(line: str) -> str:
    return line.replace('"', '').replace("'", '').replace('\\', '')


FED_EXPR_PLAIN = _unquote(FED_EXPR)


def flag_assignments(line: str) -> List[str]:
    """The value text of every flag assignment on a code line (quotes ignored).

    The line is split at every occurrence of the flag key, so ``X=0; X=1`` yields both values."""
    plain = _unquote(line)
    keys = list(_FLAG_KEY_RE.finditer(plain))
    ends = [m.start() for m in keys[1:]] + [len(plain)]
    return [plain[m.end():end] for m, end in zip(keys, ends)]


def is_fed_value(rest: str) -> bool:
    """True when the assigned value is exactly the enterprise-fed tier expression."""
    if not rest.strip().startswith(FED_EXPR_PLAIN):
        return False
    after = rest.strip()[len(FED_EXPR_PLAIN):].strip()
    return not after or after[0] in ',}#;&|'


def _check_job_head(text: str) -> str:
    """The ``check`` job from its header to its ``steps:`` key (the job-level env lives there)."""
    start = re.search(r'^  check:\s*$', text, re.M)
    if not start:
        return ''
    rest = text[start.end():]
    nxt = _JOB_RE.search(rest)
    body = rest[:nxt.start()] if nxt else rest
    return body.split('\n    steps:', 1)[0]


def default_on_failures(ci_text: str, code: List[str]) -> List[str]:
    """Reasons the G1 default-on posture does not hold; empty when it does."""
    problems: List[str] = []
    for ln in code:
        for rest in flag_assignments(ln):
            if not (_ZERO_RE.match(rest) or is_fed_value(rest)):
                problems.append('flag assignment is neither 0 nor the enterprise-fed expression: %s' % ln.strip()[:120])
    head = _check_job_head(ci_text)
    keyed = [ln for ln in code if any(is_fed_value(r) for r in flag_assignments(ln))]
    in_head = [ln for ln in _code_lines(head) if any(is_fed_value(r) for r in flag_assignments(ln))]
    if len(keyed) != 1 or len(in_head) != 1:
        problems.append('the enterprise-fed expression must be set exactly once, in the check job env (found %d)'
                        % len(keyed))
    if not all(leg in head for leg in FED_LEGS):
        problems.append('the check matrix lost an enterprise-fed fed leg')
    if not any(RUN_GUARD in ln for ln in code):
        problems.append('the run step lost its own guard (flag 1, CI_PG_ISOLATE_OFF not 1, tier enterprise-fed)')
    if not KILL_BRANCH_RE.search(ci_text):
        problems.append('the CI_PG_ISOLATE_OFF kill-switch branch no longer forces the flag to 0')
    return problems


def static_failures(ci_text: str, repo: Path) -> List[Failure]:
    """Every failed ci.yml invariant as ``(id, message)``; empty when all hold."""
    del repo  # kept for a stable signature; ci.yml checks are text-only
    out: List[Failure] = []
    code = _code_lines(ci_text)
    default_on = default_on_failures(ci_text, code)
    if default_on:
        out.append(('G1-default-on', '%s must be 1 only for the enterprise-fed tier of the fed legs '
                    '(decision 919f1943, 3-agent vote (6def5ab6)): %s' % (FLAG, '; '.join(default_on))))
    calls = [ln for ln in code if WRAPPER in ln]
    if any(WRAPPER + ' sweep' in ln for ln in calls):
        out.append(('G2-no-ci-sweep', 'ci.yml runs the admin-only cross-run sweep'))
    if any(re.search(r'(^|\s)--url(\s|=|$)', ln) for ln in calls):
        out.append(('G3-no-url-argv', 'a %s call in ci.yml passes the URL in argv' % WRAPPER))
    if not (any(WRAPPER + ' setup' in ln for ln in calls)
            and any(WRAPPER + ' teardown' in ln for ln in calls)):
        out.append(('G4-setup-teardown', 'ci.yml must run both %s setup and teardown' % WRAPPER))
    if PREBUILD not in ci_text:
        out.append(('G5-prebuild-selection', 'the isolated lane must prebuild with: ' + PREBUILD))
    if WATCHDOG not in ci_text:
        out.append(('G6-watchdog', 'the isolated lane lost its watchdog line: ' + WATCHDOG))
    uploads = [s for s in _steps(ci_text)
               if 'actions/upload-artifact@' in s and LOG_PATH in s and 'always()' in s]
    if not uploads:
        out.append(('G7-log-upload', 'no if: always() upload step for %s' % LOG_PATH))
    if KILL_VAR not in ci_text:
        out.append(('G8-kill-switch', 'the %s kill switch is not wired' % KILL_VAR))
    if TEMPLATE_GUARD not in ci_text:
        out.append(('G9-template-guard', 'the lane does not fail closed without the template'))
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
