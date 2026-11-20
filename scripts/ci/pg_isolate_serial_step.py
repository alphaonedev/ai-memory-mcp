#!/usr/bin/env python3
"""The serial shard isolated-binaries step of the linux-fed enterprise-fed leg (#9592).

3-agent vote (71472661), decision A (step-scoped opt-in): this is the ONE
workflow step that sets AI_MEMORY_TEST_PG_ISOLATE=1. It runs the serial-shard
binaries that "Run tests" deferred to it (``$RUNNER_TEMP/ci-iso-mode.txt`` is
``deferred``) through scripts/test/pg_isolated_binary.py, one Postgres clone per
binary, the residual list alone on the shared database after the pool drains,
``--test-threads=1`` unchanged. It fails closed on: a wrapper exit other than
0, a missing log, a log without its current_database evidence line or its
``test result:`` line, a zero-test binary, a binary that is not on a clone of
this run, two binaries on one clone, a residual off the shared database, a
self-skipped PG test, a teardown failure and any clone or template left after
teardown. Teardown and the leftover check run in ``finally`` and on SIGTERM /
SIGINT (I-11); the always() Cleanup step runs ``cleanup`` again.

CI_PG_ISOLATE_OFF=1 (kill switch, I-9) runs the exact serial path instead:
``cargo test --no-fail-fast --features sal-postgres --test ... -- --test-threads=1``.

The connection URL comes only from AI_MEMORY_TEST_POSTGRES_URL in the
environment; it is never put on argv and never printed (every printed line is
URL-redacted). Teardown always gets AI_MEMORY_TEST_PG_TEMPLATE, the run id and
a ``--db`` that equals the URL database explicitly (PR 9686), and no decision
here reads the text of a wrapper refusal: only its exit status.

Usage: pg_isolate_serial_step.py run | leftovers | cleanup
Exit 0 success, 1 a fail-closed reason (one ``[#9592] ... FAIL:`` line each).
"""
from __future__ import annotations

import argparse
import importlib.util
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

TAG = '[#9592]'
URL_VAR = 'AI_MEMORY_TEST_POSTGRES_URL'
FLAG_VAR = 'AI_MEMORY_TEST_PG_ISOLATE'
TEMPLATE_VAR = 'AI_MEMORY_TEST_PG_TEMPLATE'
RUN_ID_VAR = 'AI_MEMORY_TEST_PG_RUN_ID'
KILL_VAR = 'CI_PG_ISOLATE_OFF'
DB_VAR = 'CI_FED_DB'
MODE_FILE = 'ci-iso-mode.txt'
SHARD_DIR = 'ci-shard'
TARGETS_FILE = 'iso_targets.txt'
RESIDUAL_FILE = 'iso_residual.txt'
LOG_DIR = 'iso-logs'
JOBS = '8'
FEATURES = ['--features', 'sal-postgres']
TEST_ARGS = ['--test-arg=--test-threads=1', '--test-arg=--show-output']
WATCHDOG_CAP_SECS = 7800
WATCHDOG_MARGIN_SECS = 300
KILL_AFTER = '--kill-after=60'
SETUP_TIMEOUT_SECS = 900
TERM_WAIT_SECS = 90
SKIP_LINE_MAX = 200
LOG_MAX_BYTES = 256 * 1024 * 1024
HERE = Path(os.path.realpath(__file__)).parent
WRAPPER = HERE.parent / 'test' / 'pg_isolated_binary.py'
PARITY = HERE / 'pg_isolate_parity.py'

EVIDENCE_RE = re.compile(r'^# \[pg_isolated_binary\] current_database=([A-Za-z0-9_<>]{1,63}) mode=(isolated|residual)$')
TARGET_RE = re.compile(r'^--test ([A-Za-z0-9_]{1,128})$')
NAME_RE = re.compile(r'^[A-Za-z0-9_]{1,128}$')
DIGITS_RE = re.compile(r'^[1-9][0-9]{0,8}$')
ENV_LINE_RE = re.compile(r'^AI_MEMORY_TEST_PG_(?:RUN_ID|TEMPLATE)=[a-z0-9_]{1,63}$')
URL_RE = re.compile(r'[A-Za-z][A-Za-z0-9+.-]{0,30}://\S*')
SKIP_RE = re.compile(r'\bskip(?:ping|ped)?\b', re.IGNORECASE)
SKIP_MARKERS = ('AI_MEMORY_TEST_POSTGRES_URL', 'PostgresStore', 'connect failed', 'cannot reach')
WRAPPER_EXITS = {2: 'wrapper error', 3: 'clone mint/hold failure', 4: 'wrapper refused',
                 124: 'watchdog expired', 143: 'terminated'}


class StepCancelled(Exception):
    """A SIGTERM / SIGINT reached the step; teardown still runs."""

    def __init__(self, signum: int) -> None:
        super().__init__('cancelled by signal %d' % signum)
        self.signum = signum


class StepFail(Exception):
    """One fail-closed reason that ends the step before the wrapper run."""


def redact(text: str) -> str:
    return URL_RE.sub('<redacted-url>', text)


def say(line: str) -> None:
    print(redact('%s %s' % (TAG, line)), flush=True)


def fail(reason: str) -> None:
    say('serial shard step FAIL: %s' % reason)


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, str(path))
    if spec is None or spec.loader is None:
        raise ImportError('cannot load %s' % path.name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_MODULES: dict = {}


def wrapper():
    """The isolation wrapper, by its real path (never sys.path); a failed load is a fail-closed reason."""
    if 'w' not in _MODULES:
        try:
            _MODULES['w'] = _load('pg_isolated_binary_9592', WRAPPER)
        except (Exception, SystemExit) as exc:
            raise StepFail('cannot load pg_isolated_binary.py (%s)' % type(exc).__name__) from None
    return _MODULES['w']


def parity():
    if 'p' not in _MODULES:
        try:
            _MODULES['p'] = _load('pg_isolate_parity_9592', PARITY)
        except (Exception, SystemExit) as exc:
            raise StepFail('cannot load pg_isolate_parity.py (%s)' % type(exc).__name__) from None
    return _MODULES['p']


def watchdog_secs(env: dict, now: float) -> int:
    """min(cap, job time left - margin); an absent or malformed timer gives the cap (like ci.yml #6795)."""
    minutes, t0 = env.get('JOB_TIMEOUT_MIN', ''), env.get('JOB_T0', '')
    if not (DIGITS_RE.match(minutes) and re.match(r'^[1-9][0-9]{0,11}$', t0)):
        return WATCHDOG_CAP_SECS
    left = int(minutes) * 60 - (int(now) - int(t0)) - WATCHDOG_MARGIN_SECS
    return min(WATCHDOG_CAP_SECS, left)


def serial_argv(selection: list[str]) -> list[str]:
    """The exact serial path (kill switch): unchanged ``--test-threads=1``."""
    return ['cargo', 'test', '--no-fail-fast'] + FEATURES + list(selection) + ['--', '--test-threads=1']


def prebuild_argv(selection: list[str]) -> list[str]:
    return ['cargo', 'test', '--no-run'] + FEATURES + list(selection)


def self_skip_lines(text: str) -> list[str]:
    """Lines where a PG test says it skipped itself (I-6); bounded, URL-redacted, wrapper lines ignored."""
    hits = []
    for line in text.splitlines():
        if line.lstrip().startswith('#') or not SKIP_RE.search(line):
            continue
        if any(marker in line for marker in SKIP_MARKERS):
            hits.append(redact(line.strip())[:SKIP_LINE_MAX])
    return hits


def _names(path: Path, pattern: re.Pattern) -> list[str]:
    out = []
    for raw in path.read_text(encoding='utf-8').splitlines():
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        m = pattern.match(line)
        if not m:
            raise StepFail('malformed line in %s: %r' % (path.name, line[:80]))
        out.append(m.group(1) if m.groups() else line)
    return out


def _shared_db(env: dict) -> str:
    url = env.get(URL_VAR, '')
    db = env.get(DB_VAR, '')
    if not url:
        raise StepFail('%s is not set' % URL_VAR)
    w = wrapper()
    if not db or db != w.database_name(url) or not w._IDENT_RE.match(db):
        raise StepFail('%s does not name the database of %s' % (DB_VAR, URL_VAR))
    return db


def _child_env(env: dict, **extra: str) -> dict:
    child = dict(env)
    child.update(extra)
    return child


def _teardown(host, env: dict, db: str, tpl: str, run_id: str) -> list[str]:
    """Teardown with the template, run id and URL database explicit, then ONE leftover check."""
    reasons = []
    argv = [sys.executable, str(WRAPPER), 'teardown', '--db', db, '--run-id', run_id]
    try:
        rc = host.run(argv, _child_env(env, **{TEMPLATE_VAR: tpl, RUN_ID_VAR: run_id}))
        if rc != 0:
            reasons.append('wrapper teardown failed (exit %d)' % rc)
    except StepCancelled as exc:
        reasons.append('teardown interrupted (%s)' % exc)
    try:
        clones, template = host.leftovers(env, db, run_id)
    except (Exception, StepCancelled) as exc:  # a check that cannot run proves nothing: fail closed
        reasons.append('leftover check failed (%s)' % type(exc).__name__)
        return reasons
    say('isolation leftovers after teardown: clones=%d template=%d' % (clones, template))
    if clones or template:
        reasons.append('leftover clones after teardown: clones=%d template=%d' % (clones, template))
    return reasons


def _log_reasons(log_dir: Path, names: list[str], residual: set[str], shared_db: str, prefix: str):
    reasons, seen = [], {}
    counts = {'isolated': 0, 'residual': 0}
    for name in names:
        path = log_dir / (name + '.log')
        try:
            if path.stat().st_size > LOG_MAX_BYTES:
                reasons.append('log over %d bytes: %s' % (LOG_MAX_BYTES, name))
                continue
            text = path.read_text(encoding='utf-8', errors='replace')
        except OSError:
            reasons.append('missing log: %s' % name)
            continue
        first = text.split('\n', 1)[0]
        m = EVIDENCE_RE.match(first)
        if not m:
            reasons.append('no current_database evidence line: %s' % name)
            continue
        db, mode = m.group(1), m.group(2)
        segs = [s for s in parity().segments(text) if s.name == name]
        if len(segs) != 1 or segs[0].totals is None:
            reasons.append('no test result line: %s' % name)
            continue
        bad = parity().structural(segs[0], 'isolated')
        if bad:
            reasons.append(bad)
            continue
        if name in residual:
            if mode != 'residual' or db != shared_db:
                reasons.append('residual not on the shared database: %s' % name)
                continue
        elif mode != 'isolated' or not db.startswith(prefix):
            reasons.append('not on a clone of this run: %s (current_database=%s)' % (name, db))
            continue
        else:
            if db in seen:
                reasons.append('duplicate database: %s and %s share %s' % (seen[db], name, db))
                continue
            seen[db] = name
        counts[mode] += 1
        reasons += ['self-skipped PG test in %s: %s' % (name, hit) for hit in self_skip_lines(text)]
    return reasons, counts


def _read_inputs(env: dict):
    temp = env.get('RUNNER_TEMP', '')
    try:
        if not temp:
            raise OSError('RUNNER_TEMP unset')
        mode = (Path(temp) / MODE_FILE).read_text(encoding='utf-8').strip()
    except OSError:
        raise StepFail('cannot read the isolation mode file') from None
    if mode == 'none':
        return None
    if mode != 'deferred':
        raise StepFail('unknown isolation mode %r' % mode[:40])
    shard = Path(temp) / SHARD_DIR
    try:
        targets = _names(shard / TARGETS_FILE, TARGET_RE)
        residual = _names(shard / RESIDUAL_FILE, NAME_RE)
    except OSError:
        raise StepFail('cannot read %s or %s' % (TARGETS_FILE, RESIDUAL_FILE)) from None
    if not targets:
        raise StepFail('deferred mode but %s lists no binary' % TARGETS_FILE)
    if len(set(targets)) != len(targets):
        raise StepFail('%s names a binary twice' % TARGETS_FILE)
    extra = sorted(set(residual) - set(targets))
    if extra:
        raise StepFail('residual binaries not in %s: %s' % (TARGETS_FILE, ', '.join(extra)))
    return shard, targets, set(residual)


def run_step(host, env: dict) -> int:
    started = host.now()
    try:
        inputs = _read_inputs(env)
        if inputs is None:
            say('no serial-shard binaries were deferred to this step')
            return 0
        shard, targets, residual = inputs
        selection = [part for name in targets for part in ('--test', name)]
        secs = watchdog_secs(env, host.now())
        if secs <= 0:
            raise StepFail('no job time left for the serial shard step')
        timeout = host.which('timeout')
        if not timeout:
            raise StepFail('timeout is not on PATH')
        watchdog = [timeout, '--signal=TERM', KILL_AFTER, str(secs)]
        if env.get(KILL_VAR) == '1':
            return _serial_path(host, env, selection, watchdog)
        if env.get(FLAG_VAR) != '1':
            raise StepFail('the step env does not set %s=1' % FLAG_VAR)
        db = _shared_db(env)
        w = wrapper()
        tpl, run_id = w.template_name(db), w.new_run_id()
        log_dir = shard / LOG_DIR
        if log_dir.exists() and any(log_dir.iterdir()):
            raise StepFail('the log directory already holds logs: %s' % log_dir)
    except StepFail as exc:
        fail(str(exc))
        return 1
    host.append_env('%s=%s' % (RUN_ID_VAR, run_id))
    host.append_env('%s=%s' % (TEMPLATE_VAR, tpl))
    reasons: list[str] = []
    counts = {'isolated': 0, 'residual': 0}
    try:
        reasons, counts = _isolated(host, env, shard, targets, residual, selection, watchdog, db, tpl, run_id)
    except StepCancelled as exc:
        reasons.append(str(exc))
    finally:
        reasons += _teardown(host, env, db, tpl, run_id)
    say('serial shard step wall time: %ds, jobs=%s, binaries=%d' % (int(host.now() - started), JOBS, len(targets)))
    for reason in reasons:
        fail(reason)
    if reasons:
        return 1
    say('serial shard isolated binaries ok: binaries=%d isolated=%d residual=%d'
        % (len(targets), counts['isolated'], counts['residual']))
    return 0


def _serial_path(host, env: dict, selection: list[str], watchdog: list[str]) -> int:
    say('per-binary Postgres isolation disabled by %s=1: running the serial path' % KILL_VAR)
    serial_env = _child_env(env, **{FLAG_VAR: '0'})
    rc = host.run(prebuild_argv(selection), serial_env)
    if rc != 0:
        fail('prebuild failed (exit %d)' % rc)
        return 1
    rc = host.run(watchdog + serial_argv(selection), serial_env)
    if rc != 0:
        fail('serial path test failures (exit %d)' % rc)
        return 1
    say('serial path ok: binaries=%d' % (len(selection) // 2))
    return 0


def _isolated(host, env, shard, targets, residual, selection, watchdog, db, tpl, run_id):
    rc = host.run(prebuild_argv(selection), env)
    if rc != 0:
        return ['prebuild failed (exit %d)' % rc], {'isolated': 0, 'residual': 0}
    rc, out = host.capture([sys.executable, str(WRAPPER), 'setup', '--db', db, '--jobs', JOBS,
                            '--run-id', run_id, '--emit-env'], env)
    if rc != 0:
        return ['wrapper setup failed (exit %d)' % rc], {'isolated': 0, 'residual': 0}
    emitted = dict(line.split('=', 1) for line in out.splitlines() if '=' in line)
    if TEMPLATE_VAR not in emitted:
        return ['setup emitted no %s' % TEMPLATE_VAR], {'isolated': 0, 'residual': 0}
    if emitted[TEMPLATE_VAR] != tpl:
        return ['setup template is not %s' % tpl], {'isolated': 0, 'residual': 0}
    if emitted.get(RUN_ID_VAR, run_id) != run_id:
        return ['setup run id is not %s' % run_id], {'isolated': 0, 'residual': 0}
    log_dir = shard / LOG_DIR
    argv = watchdog + [sys.executable, str(WRAPPER), 'run', '--targets-file', str(shard / TARGETS_FILE),
                       '--residual-file', str(shard / RESIDUAL_FILE), '--jobs', JOBS, '--log-dir', str(log_dir),
                       '--run-id', run_id] + TEST_ARGS + ['--', 'cargo', 'test', '--no-fail-fast'] + FEATURES
    rc = host.run(argv, _child_env(env, **{FLAG_VAR: '1', TEMPLATE_VAR: tpl, RUN_ID_VAR: run_id}))
    reasons = []
    if rc != 0:
        reasons.append('%s (exit %d)' % (WRAPPER_EXITS.get(rc, 'test failures'), rc))
    more, counts = _log_reasons(log_dir, targets, residual, db, wrapper().run_prefix(run_id))
    return reasons + more, counts


def cmd_leftovers(host, env: dict) -> int:
    run_id = env.get(RUN_ID_VAR, '')
    if not run_id:
        say('no isolation run id: nothing to check')
        return 0
    try:
        db = _shared_db(env)
        if not wrapper().valid_run_id(run_id):
            raise StepFail('%s is not a valid run id' % RUN_ID_VAR)
        clones, template = host.leftovers(env, db, run_id)
    except StepFail as exc:
        fail(str(exc))
        return 1
    say('isolation leftovers after teardown: clones=%d template=%d' % (clones, template))
    return 1 if clones or template else 0


def cmd_cleanup(host, env: dict) -> int:
    """I-11: the always() Cleanup step tears this run down again, then proves nothing is left."""
    run_id = env.get(RUN_ID_VAR, '')
    if not run_id:
        say('no isolation run id: no isolation run to clean up')
        return 0
    try:
        db = _shared_db(env)
        w = wrapper()
        if not w.valid_run_id(run_id):
            raise StepFail('%s is not a valid run id' % RUN_ID_VAR)
        tpl = w.template_name(db)
        if env.get(TEMPLATE_VAR) not in (None, '', tpl):
            raise StepFail('%s is not %s' % (TEMPLATE_VAR, tpl))
    except StepFail as exc:
        fail(str(exc))
        return 1
    reasons = _teardown(host, env, db, tpl, run_id)
    for reason in reasons:
        fail(reason)
    return 1 if reasons else 0


class Host:
    """The real side effects: processes, $GITHUB_ENV, the leftover count (libpq env, never argv)."""

    def __init__(self) -> None:
        self.cancelled: int | None = None

    def on_signal(self, signum: int, _frame: object) -> None:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)  # teardown must finish: later signals are ignored
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        self.cancelled = signum
        raise StepCancelled(signum)

    def now(self) -> float:
        return time.time()

    def which(self, name: str) -> str | None:
        return shutil.which(name)

    def append_env(self, line: str) -> None:
        if not ENV_LINE_RE.match(line):
            raise StepFail('refusing an env line of unexpected shape')
        target = os.environ.get('GITHUB_ENV')
        if target:
            with Path(target).open('a', encoding='utf-8') as handle:
                handle.write(line + '\n')

    def capture(self, argv: list[str], env: dict) -> tuple[int, str]:
        done = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=SETUP_TIMEOUT_SECS)
        for line in (done.stderr or '').splitlines():
            print(redact(line), file=sys.stderr, flush=True)
        return done.returncode, done.stdout or ''

    def run(self, argv: list[str], env: dict) -> int:
        child = subprocess.Popen(argv, env=env)
        try:
            return child.wait()
        except StepCancelled:
            child.send_signal(signal.SIGTERM)
            try:
                child.wait(timeout=TERM_WAIT_SECS)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
            raise

    def leftovers(self, env: dict, db: str, run_id: str) -> tuple[int, int]:
        w = wrapper()
        prefix, tpl = w.run_prefix(w.checked_run_id(run_id)), w._checked_ident(w.template_name(db))
        sql = ("SELECT (SELECT count(*) FROM pg_database WHERE starts_with(datname, '%s')) || '|' || "
               "(SELECT count(*) FROM pg_database WHERE datname = '%s')" % (prefix, tpl))
        raw = w.psql(env[URL_VAR], sql, tuples=True).strip().split('|')
        if len(raw) != 2 or not all(part.isdigit() for part in raw):
            raise StepFail('unreadable leftover count')
        return int(raw[0]), int(raw[1])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split('\n', 1)[0])
    parser.add_argument('command', choices=('run', 'leftovers', 'cleanup'))
    args = parser.parse_args(argv)
    host = Host()
    signal.signal(signal.SIGTERM, host.on_signal)
    signal.signal(signal.SIGINT, host.on_signal)
    env = dict(os.environ)
    try:
        if args.command == 'run':
            return run_step(host, env)
        if args.command == 'leftovers':
            return cmd_leftovers(host, env)
        return cmd_cleanup(host, env)
    except StepCancelled as exc:
        fail(str(exc))
        return 1


if __name__ == '__main__':
    sys.exit(main())
