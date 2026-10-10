#!/usr/bin/env python3
"""Invariants of the opt-in per-binary Postgres isolation lane (#6383 / #6386).

Replaces the r1 shell Section G of scripts/test/test-ci-workflow-invariants.sh
(review r1 L1). Checks, each with an id that names its review finding:

G1-opt-in              ci.yml never turns AI_MEMORY_TEST_PG_ISOLATE on (no
                       ``=`` assignment other than 0, no YAML env key). M4.
G2-no-ci-sweep         ci.yml never runs the admin-only cross-run sweep. H2.
G3-no-url-argv         no wrapper call in ci.yml passes ``--url``. L3.
G4-setup-teardown      ci.yml runs both ``setup`` and ``teardown``.
G5-prebuild-selection  the isolated lane prebuilds only its selected targets. H1.
G6-watchdog            the isolated lane keeps the #1492 watchdog line.
G7-log-upload          an ``if: always()`` upload step ships the per-binary logs. M3.
G8-kill-switch         the CI_PG_ISOLATE_OFF repo variable is wired.
G9-template-guard      the lane fails closed without the template. M1/M6.
G10-split-wired        run_sharded() calls ``python3 -I pg_isolate_split.py``
                       exactly once, as the sole body of the PG_ISO_LANE
                       guard, after the partition and before the first
                       run_shard launch, failing closed. #7052.
run-help               ``pg_isolated_binary.py run --help`` EXECUTES and
                       lists its flags (C1, L2: not a docstring grep).
source                 neither the wrapper nor the Rust helper drops WITH
                       FORCE, and the wrapper checks pg_stat_activity.

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
# #7052: the split that moves the --test/--bin binaries into the isolated lane.
# Pinned verbatim: ``-I`` (#6956 posture), the three files, and ``|| return``
# (fail closed) are all part of the contract.
SPLIT_SCRIPT = 'scripts/ci/pg_isolate_split.py'
SPLIT = ('python3 -I %s --build-json "$sd/build.jsonl" --serial-file "$sd/serial.txt" '
         '--out-dir "$sd" || return "$?"' % SPLIT_SCRIPT)
SPLIT_GUARD = 'if [ "$PG_ISO_LANE" = "1" ]; then'
PARTITION = 'scripts/ci/partition_test_binaries.py --build-json'
SHARD_LAUNCH = '( run_shard '

_ASSIGN_RE = re.compile(r'\b%s=(?!0\b)' % FLAG)
_YAML_KEY_RE = re.compile(r'^\s*%s\s*:' % FLAG, re.M)
_STEP_RE = re.compile(r'^\s*- name:', re.M)

Failure = Tuple[str, str]


def _code_lines(text: str) -> List[str]:
    return [ln for ln in text.splitlines() if not ln.lstrip().startswith('#')]


def _steps(text: str) -> List[str]:
    starts = [m.start() for m in _STEP_RE.finditer(text)] + [len(text)]
    return [text[a:b] for a, b in zip(starts, starts[1:])]


def _function_body(text: str, name: str) -> Optional[str]:
    """Body of the shell function ``name() {`` ... ``}`` at the same indent."""
    m = re.search(r'^(\s*)%s\(\) \{\n' % re.escape(name), text, re.M)
    if not m:
        return None
    end = text.find('\n%s}\n' % m.group(1), m.end())
    return None if end < 0 else text[m.end():end]


def split_failure(ci_text: str) -> Optional[str]:
    """G10 (#7052): ``None`` when the PG_ISO_LANE split is wired as pinned.

    The split must be called exactly once in ci.yml, inside ``run_sharded()``,
    verbatim (``-I``, the three files, ``|| return "$?"``), as the sole body of
    the ``PG_ISO_LANE`` guard, after the single partition call and before the
    first ``run_shard`` launch (the first step that runs tests).
    """
    if sum(SPLIT_SCRIPT in ln for ln in _code_lines(ci_text)) != 1:
        return 'ci.yml must call %s exactly once, inside run_sharded()' % SPLIT_SCRIPT
    body = _function_body(ci_text, 'run_sharded')
    if body is None:
        return 'run_sharded() not found in ci.yml'
    lines = [ln.strip() for ln in _code_lines(body) if ln.strip()]
    hits = [i for i, ln in enumerate(lines) if ln == SPLIT]
    if len(hits) != 1:
        return 'run_sharded() must contain exactly once the line: ' + SPLIT
    i = hits[0]
    if i == 0 or lines[i - 1] != SPLIT_GUARD or i + 1 >= len(lines) or lines[i + 1] != 'fi':
        return 'the split call must be the sole body of `%s` ... `fi`' % SPLIT_GUARD
    partitions = [j for j, ln in enumerate(lines) if PARTITION in ln]
    if len(partitions) != 1 or partitions[0] > i:
        return 'the split must follow the single partition call (%s)' % PARTITION
    launches = [j for j, ln in enumerate(lines) if ln.startswith(SHARD_LAUNCH)]
    if not launches or min(launches) < i:
        return 'the split must precede the first run_shard launch'
    return None


def static_failures(ci_text: str, repo: Path) -> List[Failure]:
    """Every failed ci.yml invariant as ``(id, message)``; empty when all hold."""
    del repo  # kept for a stable signature; ci.yml checks are text-only
    out: List[Failure] = []
    code = _code_lines(ci_text)
    assigns = [ln.strip() for ln in code if _ASSIGN_RE.search(ln)]
    if assigns or _YAML_KEY_RE.search(ci_text):
        out.append(('G1-opt-in', 'ci.yml turns %s on (opt-in; vote 4d3ea1c5): %s'
                    % (FLAG, assigns[:3] or 'YAML env key')))
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
    split = split_failure(ci_text)
    if split:
        out.append(('G10-split-wired', split))
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
    print('ok: pg-isolation invariants hold (G1-G10, run-help, source)')
    return 0


if __name__ == '__main__':
    sys.exit(main())
