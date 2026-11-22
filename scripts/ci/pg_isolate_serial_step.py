#!/usr/bin/env python3
"""The serial shard isolated-binaries step of the linux-fed enterprise-fed leg (#9592).

3-agent vote (71472661), decision A (step-scoped opt-in): this is the ONE
workflow step that sets AI_MEMORY_TEST_PG_ISOLATE=1. It runs the serial-shard
binaries that "Run tests" deferred to it (``$RUNNER_TEMP/ci-iso-mode.txt`` is
``deferred``) through scripts/test/pg_isolated_binary.py, one Postgres clone per
binary, the residual list alone on the shared database after the pool drains,
``--test-threads=1`` unchanged.

ONE completion ledger is the single source of "what ran" (fix notice 9592 r1):
"Run tests" writes the deferred list (``ci-shard/iso_targets.txt``) and the mode
file; this step writes the run id to ``ci-iso-run.txt`` before the first clone
and, only on a green run, ``ci-iso-ledger.txt``: one row per deferred binary
(tests, ignored, mode, database), then ``complete binaries=N run_id=ID`` as the
LAST row (the done marker). The always() Cleanup step (``cleanup``) tears the
run down again and is red unless the ledger matches the deferred list exactly
and no clone or template is left.

Every unset, empty or misspelled input is red, never "nothing to do": the mode
file, the kill switch (CI_PG_ISOLATE_OFF accepts 1/true/on and 0/false/off or
empty, case-insensitive; anything else, or the name absent from the step env,
is red), the run id, GITHUB_ENV, the template and CI_FED_DB. The mode and the
kill switch must agree: with the kill switch on, "Run tests" ran the
serial-shard binaries itself with ``--test-threads=1`` (mode ``killswitch``)
and this step only proves that nothing was deferred.

The step fails closed on: a wrapper exit other than 0, a missing log, a log
without its current_database evidence line, its binary path or its ``test
result:`` line, a log whose test lines do not prove its result line
(pg_isolate_parity.evidence_reason: no test line at all, an extra result line
outside a captured-output body, ok / FAILED / ignored lines that differ from
the totals, or any test filtered out), a binary that is not on a clone of
this run, two binaries on one clone, a residual off the shared database, any
test that prints a skip message, ignored test names that differ from the
binary's own ``--list --ignored``, a teardown failure and any clone or template
left after teardown. Teardown, the leftover check and the log redaction run in
``finally`` and on SIGTERM / SIGINT (I-11).

The connection URL comes only from AI_MEMORY_TEST_POSTGRES_URL in the
environment; it is never put on argv and never printed: every printed line,
every streamed child line and every log file left for the pg-iso-logs artifact
goes through ``redact``. Teardown always gets AI_MEMORY_TEST_PG_TEMPLATE, the
run id and a ``--db`` that equals the URL database explicitly (PR 9686), and no
decision here reads the text of a wrapper refusal: only its exit status.

Usage: pg_isolate_serial_step.py run | leftovers | cleanup | killswitch | redact-logs
Exit 0 success, 1 a fail-closed reason (one ``[#9592] ... FAIL:`` line each).
``killswitch`` prints ``on`` or ``off`` (the value "Run tests" acts on).
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
import threading
import time
from pathlib import Path

TAG = '[#9592]'
FAIL_PREFIX = 'serial shard step FAIL: '
URL_VAR = 'AI_MEMORY_TEST_POSTGRES_URL'
FLAG_VAR = 'AI_MEMORY_TEST_PG_ISOLATE'
TEMPLATE_VAR = 'AI_MEMORY_TEST_PG_TEMPLATE'
RUN_ID_VAR = 'AI_MEMORY_TEST_PG_RUN_ID'
KILL_VAR = 'CI_PG_ISOLATE_OFF'
DB_VAR = 'CI_FED_DB'
TEMP_VAR = 'RUNNER_TEMP'
MODE_FILE = 'ci-iso-mode.txt'
RUN_FILE = 'ci-iso-run.txt'
LEDGER_FILE = 'ci-iso-ledger.txt'
SHARD_DIR = 'ci-shard'
TARGETS_FILE = 'iso_targets.txt'
RESIDUAL_FILE = 'iso_residual.txt'
LOG_DIR = 'iso-logs'
MODES = ('none', 'deferred', 'killswitch')
KILL_ON = ('1', 'true', 'on')
KILL_OFF = ('', '0', 'false', 'off')
KILL_BAD_REASON = 'CI_PG_ISOLATE_OFF has an unrecognised value'
JOBS = '8'
FEATURES = ['--features', 'sal-postgres']
TEST_ARGS = ['--test-arg=--test-threads=1', '--test-arg=--show-output']
LIST_IGNORED = ['--list', '--ignored']
WATCHDOG_CAP_SECS = 7800
WATCHDOG_MARGIN_SECS = 300
KILL_AFTER = '--kill-after=60'
SETUP_TIMEOUT_SECS = 900
TERM_WAIT_SECS = 90
PUMP_JOIN_SECS = 30
SKIP_LINE_MAX = 200
SKIP_SCAN_CHARS = 4096
SKIP_HITS_MAX = 50
LOG_MAX_BYTES = 256 * 1024 * 1024
LEDGER_MAX_BYTES = 1024 * 1024
RUN_FILE_MAX_BYTES = 256
REASONS_MAX = 40
NAMES_SHOWN_MAX = 20
STREAM_LINE_MAX = 64 * 1024
TRUNCATED_MARK = ' [line truncated]'
REDACTED = '<redacted-url>'
WRAPPER_LINE_PREFIX = '# [pg_isolated_binary]'
HERE = Path(os.path.realpath(__file__)).parent
WRAPPER = HERE.parent / 'test' / 'pg_isolated_binary.py'
PARITY = HERE / 'pg_isolate_parity.py'
SECRET_REDACT = HERE / 'secret_redact.py'

EVIDENCE_RE = re.compile(r'^# \[pg_isolated_binary\] current_database=([A-Za-z0-9_<>]{1,63}) mode=(isolated|residual)$')
TARGET_RE = re.compile(r'^--test ([A-Za-z0-9_]{1,128})$')
NAME_RE = re.compile(r'^[A-Za-z0-9_]{1,128}$')
DIGITS_RE = re.compile(r'^[1-9][0-9]{0,8}$')
T0_RE = re.compile(r'^[1-9][0-9]{0,11}$')
ENV_LINE_RE = re.compile(r'AI_MEMORY_TEST_PG_RUN_ID=[a-z0-9]{1,63}|AI_MEMORY_TEST_PG_TEMPLATE=[a-z0-9_]{1,63}')
RUN_FILE_RE = re.compile(r'AI_MEMORY_TEST_PG_RUN_ID=([a-z0-9]{1,63})\n?')
# SE: any skip word (skip, skips, skipped, skipping; any case, colon or not) is a skip print.
SKIP_RE = re.compile(r'\bskip(?:s|ping|ped)?\b', re.IGNORECASE)
LIBTEST_IGNORED = 'ignored'
TEST_LINE_RE = re.compile(r'^test \S+ \.\.\. ')
BIN_PATH_RE = re.compile(r'^\s*Running \S+ \((/?(?:[A-Za-z0-9_.+-]+/)*deps/([A-Za-z0-9_]+)-[0-9a-f]{16}(?:\.exe)?)\)\s*$')
LEDGER_ROW_RE = re.compile(r'binary ([A-Za-z0-9_]{1,128}) tests=([0-9]{1,9}) ignored=([0-9]{1,9}) '
                           r'mode=(isolated|residual) db=([A-Za-z0-9_]{1,63})')
LEDGER_DONE_RE = re.compile(r'complete binaries=([0-9]{1,9}) run_id=([a-z0-9]{1,63})')
WRAPPER_EXITS = {2: 'wrapper error', 3: 'clone mint/hold failure', 4: 'wrapper refused',
                 5: 'session bound exceeded', 124: 'watchdog expired', 143: 'terminated'}


class StepCancelled(Exception):
    """A SIGTERM / SIGINT reached the step; teardown still runs."""

    def __init__(self, signum: int) -> None:
        super().__init__('cancelled by signal %d' % signum)
        self.signum = signum


class StepFail(Exception):
    """One fail-closed reason."""


def redact(text: str) -> str:
    """``text`` through the one redaction funnel (#9750): URL, keyword, environment and quoted forms."""
    return _SECRET.redact(text, REDACTED)


def say(line: str) -> None:
    print(redact('%s %s' % (TAG, line)), flush=True)


def fail(reason: str) -> None:
    say(FAIL_PREFIX + reason)


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, str(path))
    if spec is None or spec.loader is None:
        raise ImportError('cannot load %s' % path.name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# The redaction funnel, by its real path at import: a missing or broken funnel stops the step before it
# prints anything (fail closed, #9750).
_SECRET = _load('pg_secret_redact', SECRET_REDACT)
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
    if not (DIGITS_RE.match(minutes) and T0_RE.match(t0)):
        return WATCHDOG_CAP_SECS
    left = int(minutes) * 60 - (int(now) - int(t0)) - WATCHDOG_MARGIN_SECS
    return min(WATCHDOG_CAP_SECS, left)


def prebuild_argv(selection: list[str]) -> list[str]:
    return ['cargo', 'test', '--no-run'] + FEATURES + list(selection)


def killswitch(env: dict) -> bool:
    """SF: 1/true/on is on, 0/false/off or empty is off (case-insensitive); anything else is red, never echoed."""
    value = env.get(KILL_VAR)
    if value is None:
        raise StepFail('%s is not in the step env' % KILL_VAR)
    word = value.strip().lower()
    if word in KILL_ON:
        return True
    if word in KILL_OFF:
        return False
    raise StepFail(KILL_BAD_REASON)


def self_skip_lines(text: str) -> list[str]:
    """SE: every line where a test prints a skip message (the word ``skip``, ``skips``, ``skipped`` or
    ``skipping`` in any case, with or without a colon), the text after ``test X ... `` included; the
    wrapper's own lines, libtest's ``---- X stdout ----`` and ``test result:`` lines and libtest's own
    ``ignored, <reason>`` result are not test output.
    Bounded: each line is scanned up to SKIP_SCAN_CHARS, at most SKIP_HITS_MAX hits, URL-redacted."""
    hits: list[str] = []
    for raw in text.splitlines():
        line = raw[:SKIP_SCAN_CHARS]
        if line.startswith(WRAPPER_LINE_PREFIX) or line.startswith('---- ') or line.startswith('test result:'):
            continue
        m = TEST_LINE_RE.match(line)
        body = line[m.end():] if m else line
        if m and body.startswith(LIBTEST_IGNORED):
            continue
        if SKIP_RE.search(body):
            hits.append(redact(line.strip())[:SKIP_LINE_MAX])
            if len(hits) >= SKIP_HITS_MAX:
                break
    return hits


def _capped(reasons: list[str]) -> list[str]:
    if len(reasons) <= REASONS_MAX:
        return reasons
    return reasons[:REASONS_MAX - 1] + ['%d more reasons not shown' % (len(reasons) - REASONS_MAX + 1)]


def _shown(names: list[str]) -> str:
    text = ', '.join(names[:NAMES_SHOWN_MAX])
    if len(names) > NAMES_SHOWN_MAX:
        text += ' (+%d more)' % (len(names) - NAMES_SHOWN_MAX)
    return text


def ledger_reasons(text: str, targets: list[str], run_id: str, residual: set[str], shared_db: str) -> list[str]:
    """Every reason the ledger does not prove that each deferred binary was accounted in this run.

    A row is written only for a binary whose log passed the evidence rule of ``_log_reasons``
    (pg_isolate_parity.evidence_reason: at least one test line, the totals equal to the counted
    lines, 0 filtered out; ignored names equal to ``--list --ignored``), so ``tests`` (ran) plus
    ``ignored`` is at least 1: a row with both 0 is red, an all-ignored row (tests=0, ignored>0) is not.

    A row's mode must be the one the deferred lists give its binary (residual when ``residual`` names it,
    else isolated; #9751), an isolated row must name a clone of this run and a residual row the shared
    database ``shared_db`` (an empty name proves no residual row). One linear pass; the reasons are capped
    at REASONS_MAX and the text at LEDGER_MAX_BYTES."""
    if len(text.encode('utf-8', 'replace')) > LEDGER_MAX_BYTES:
        return ['ledger over %d bytes' % LEDGER_MAX_BYTES]
    w = wrapper()
    prefix = w.run_prefix(run_id) if w.valid_run_id(run_id) else None
    deferred = set(targets)
    lines = text.splitlines()
    reasons: list[str] = []
    seen: set[str] = set()
    done: tuple[int, str] | None = None
    done_at = 0
    malformed = False
    for number, line in enumerate(lines, 1):
        if len(reasons) > REASONS_MAX:
            break
        if (row := LEDGER_ROW_RE.fullmatch(line)):
            name, mode, db = row.group(1), row.group(4), row.group(5)
            # ran + ignored; _log_reasons writes a row only after evidence_reason, so 0 here is a forged row
            tests = int(row.group(2)) + int(row.group(3))
            if name in seen:
                reasons.append('ledger names a binary twice: %s' % name)
            elif name not in deferred:
                reasons.append('ledger names a binary that was not deferred: %s' % name)
            elif tests == 0:
                reasons.append('ledger row for %s has zero tests' % name)
            elif mode != (want := 'residual' if name in residual else 'isolated'):
                reasons.append('ledger row for %s has mode %s, expected %s' % (name, mode, want))
            elif mode == 'isolated' and (prefix is None or not db.startswith(prefix)):
                reasons.append('ledger row for %s is not on a clone of this run' % name)
            elif mode == 'residual' and (not shared_db or db != shared_db):
                reasons.append('ledger row for %s is not on the shared database' % name)
            seen.add(name)
        elif (end := LEDGER_DONE_RE.fullmatch(line)):
            if done is not None:
                reasons.append('ledger has more than one complete row')
            done, done_at = (int(end.group(1)), end.group(2)), number
        else:
            malformed = True
            reasons.append('ledger row %d is malformed' % number)
    if done is None:
        if not malformed:
            reasons.append('ledger has no complete row')
        return _capped(_dedup(reasons))
    if done_at != len(lines):
        reasons.append('ledger complete row is not the last row')
    missing = [name for name in targets if name not in seen]
    if missing:
        reasons.append('ledger misses deferred binaries: %s' % _shown(missing))
    if done[0] != len(targets):
        reasons.append('ledger complete row counts %d binaries, %d deferred' % (done[0], len(targets)))
    if done[1] != run_id:
        reasons.append('ledger run id is not this run')
    return _capped(_dedup(reasons))


def _dedup(reasons: list[str]) -> list[str]:
    return list(dict.fromkeys(reasons))


def ledger_text(rows: list[tuple[str, int, int, str, str]], run_id: str) -> str:
    lines = ['binary %s tests=%d ignored=%d mode=%s db=%s' % row for row in rows]
    return '\n'.join(lines + ['complete binaries=%d run_id=%s' % (len(rows), run_id)]) + '\n'


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


def _temp(env: dict) -> Path:
    temp = env.get(TEMP_VAR, '')
    if not temp:
        raise StepFail('%s is not set' % TEMP_VAR)
    return Path(temp)


def _mode(env: dict) -> tuple[Path, str]:
    try:
        temp = _temp(env)
        mode = (temp / MODE_FILE).read_text(encoding='utf-8').strip()
    except (OSError, StepFail, UnicodeDecodeError):
        raise StepFail('cannot read the isolation mode file') from None
    if mode not in MODES:
        raise StepFail('unknown isolation mode %r' % mode[:40])
    return temp, mode


def _targets_present(temp: Path) -> bool:
    """iso_targets.txt exists and holds any non-blank text."""
    path = temp / SHARD_DIR / TARGETS_FILE
    try:
        return bool(path.read_text(encoding='utf-8', errors='replace').strip())
    except FileNotFoundError:
        return False
    except OSError:
        raise StepFail('cannot read %s' % TARGETS_FILE) from None


def _read_targets(temp: Path) -> tuple[Path, list[str], set[str]]:
    shard = temp / SHARD_DIR
    try:
        targets = _names(shard / TARGETS_FILE, TARGET_RE)
        residual = _names(shard / RESIDUAL_FILE, NAME_RE)
    except (OSError, UnicodeDecodeError):
        raise StepFail('cannot read %s or %s' % (TARGETS_FILE, RESIDUAL_FILE)) from None
    if not targets:
        raise StepFail('deferred mode but %s lists no binary' % TARGETS_FILE)
    if len(set(targets)) != len(targets):
        raise StepFail('%s names a binary twice' % TARGETS_FILE)
    extra = sorted(set(residual) - set(targets))
    if extra:
        raise StepFail('residual binaries not in %s: %s' % (TARGETS_FILE, _shown(extra)))
    return shard, targets, set(residual)


def _read_run_file(temp: Path) -> str | None:
    """The run id the step wrote before its first clone; None when the file is absent."""
    try:
        with (temp / RUN_FILE).open('rb') as handle:
            data = handle.read(RUN_FILE_MAX_BYTES + 1)
    except FileNotFoundError:
        return None
    except OSError:
        raise StepFail('cannot read %s' % RUN_FILE) from None
    m = RUN_FILE_RE.fullmatch(data.decode('utf-8', 'replace')) if len(data) <= RUN_FILE_MAX_BYTES else None
    if not m or not wrapper().valid_run_id(m.group(1)):
        raise StepFail('%s is malformed' % RUN_FILE)
    return m.group(1)


def _shared_db(env: dict) -> str:
    url = env.get(URL_VAR, '')
    db = env.get(DB_VAR, '')
    if not url:
        raise StepFail('%s is not set' % URL_VAR)
    w = wrapper()
    try:
        url_db = w.database_name(url)
    except Exception:  # an unparsable URL names no database: the same fail-closed reason
        url_db = None
    if not db or db != url_db or not w._IDENT_RE.match(db):
        raise StepFail('%s does not name the database of %s' % (DB_VAR, URL_VAR))
    return db


def _child_env(env: dict, **extra: str) -> dict:
    child = dict(env)
    child.update(extra)
    return child


def _write_atomic(path: Path, text: str) -> None:
    tmp = path.with_name('.%s.partial' % path.name)
    tmp.write_text(text, encoding='utf-8')
    os.replace(tmp, path)


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


def redact_lines(readline, emit) -> None:
    """Read byte lines through ``readline(limit)`` and ``emit`` each one URL-redacted, without its newline.

    A line over STREAM_LINE_MAX bytes keeps its first chunk only (redacted, then marked), the rest is
    read and dropped, so a URL cut at the chunk edge never leaves a partial secret: the scheme part
    of the URL stays in the redacted chunk and its tail is never emitted. Linear in the input."""
    while True:
        chunk = readline(STREAM_LINE_MAX)
        if not chunk:
            return
        truncated = False
        if not chunk.endswith(b'\n') and len(chunk) >= STREAM_LINE_MAX:
            while True:
                rest = readline(STREAM_LINE_MAX)
                if not rest:
                    break
                truncated = True
                if rest.endswith(b'\n'):
                    break
        line = redact(chunk.decode('utf-8', 'replace').rstrip('\r\n'))
        if truncated or len(line) > STREAM_LINE_MAX:
            line = line[:STREAM_LINE_MAX] + TRUNCATED_MARK
        emit(line)


def _redact_file(path: Path) -> None:
    tmp = path.with_name('.%s.redacting' % path.name)
    with path.open('rb') as src, tmp.open('w', encoding='utf-8') as dst:
        redact_lines(src.readline, lambda line: dst.write(line + '\n'))
    os.replace(tmp, path)


def _redact_dir(log_dir: Path) -> list[str]:
    """SD: rewrite every log in ``log_dir`` through ``redact`` (the pg-iso-logs artifact is public)."""
    if not log_dir.exists():
        return []
    reasons = []
    try:
        entries = sorted(log_dir.iterdir())
    except OSError:
        return ['cannot list %s for redaction' % log_dir.name]
    for path in entries:
        if path.name.startswith('.'):
            continue
        if path.is_symlink() or not path.is_file():
            reasons.append('refusing a non-regular file in %s: %s' % (log_dir.name, path.name[:80]))
            continue
        try:
            _redact_file(path)
        except OSError as exc:
            reasons.append('cannot redact %s (%s)' % (path.name[:80], type(exc).__name__))
    return reasons


def cmd_redact_logs(env: dict) -> int:
    try:
        log_dir = _temp(env) / SHARD_DIR / LOG_DIR
    except StepFail as exc:
        fail(str(exc))
        return 1
    reasons = _redact_dir(log_dir)
    for reason in reasons:
        fail(reason)
    if reasons:
        return 1
    say('isolation logs redacted: %s' % (LOG_DIR if log_dir.exists() else 'none present'))
    return 0


def _log_reasons(host, env: dict, log_dir: Path, names: list[str], residual: set[str], shared_db: str,
                 prefix: str):
    """Per-binary evidence from the logs; returns (reasons, counts, ledger rows in target order)."""
    reasons, seen, rows = [], {}, []
    counts = {'isolated': 0, 'residual': 0}
    list_env = {k: v for k, v in env.items() if k not in (URL_VAR, FLAG_VAR, TEMPLATE_VAR, RUN_ID_VAR)}
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
        m = EVIDENCE_RE.match(text.split('\n', 1)[0])
        if not m:
            reasons.append('no current_database evidence line: %s' % name)
            continue
        db, mode = m.group(1), m.group(2)
        segs = [s for s in parity().segments(text) if s.name == name]
        if not segs:
            reasons.append('no test binary path in the log: %s' % name)
            if not any(parity().RESULT_RE.match(line) for line in text.splitlines()):
                reasons.append('no test result line: %s' % name)
            continue
        if len(segs) > 1:
            reasons.append('more than one test run in the log: %s' % name)
            continue
        seg = segs[0]
        # The one evidence rule (pg_isolate_parity.evidence_reason, the core of structural; PR 9841 r1):
        # at least one test line, the real (last) result line, its three totals equal to the counted
        # test lines and 0 filtered out. An all-#[ignore] binary passes it and is then held to the
        # ignored NAMES of its own --list --ignored below (#9592 B(iii) follow-on).
        if (evidence := parity().evidence_reason(seg)) is not None:
            reasons.append(evidence)
            continue
        passed, failed, ignored = seg.totals
        if name in residual:
            if mode != 'residual' or db != shared_db:
                reasons.append('residual not on the shared database: %s' % name)
                continue
        elif mode != 'isolated' or not db.startswith(prefix):
            reasons.append('not on a clone of this run: %s (current_database=%s)' % (name, db))
            continue
        elif db in seen:
            reasons.append('duplicate database: %s and %s share %s' % (seen[db], name, db))
            continue
        else:
            seen[db] = name
        skips = self_skip_lines(text)
        if skips:
            reasons += ['self-skipped PG test in %s: %s' % (name, hit) for hit in skips]
            continue
        # The same colour-free view as parity().segments (CARGO_TERM_COLOR=always, #9592 B(iii)).
        binary = next((b.group(1) for line in text.splitlines()
                       if (b := BIN_PATH_RE.match(parity().plain(line))) and b.group(2) == name), None)
        if binary is None or '..' in binary.split('/'):
            reasons.append('no test binary path in the log: %s' % name)
            continue
        rc, out = host.capture([binary] + LIST_IGNORED, list_env)
        if rc != 0:
            reasons.append('cannot list ignored tests of %s (exit %d)' % (name, rc))
            continue
        if (unlisted := parity().ignored_reason(seg, parity().listed_names(out))) is not None:
            reasons.append(unlisted)
            continue
        counts[mode] += 1
        rows.append((name, passed + failed, ignored, mode, db))
    return reasons, counts, rows


def _step_inputs(env: dict):
    """The kill switch and the mode file must agree; returns None for a green no-op, else the deferred inputs."""
    kill = killswitch(env)
    temp, mode = _mode(env)
    present = _targets_present(temp)
    if kill:
        if mode != 'killswitch':
            raise StepFail('the kill switch is on but the mode file says %s' % mode)
        if present:
            raise StepFail('mode killswitch but %s lists binaries' % TARGETS_FILE)
        say('per-binary Postgres isolation disabled by %s: Run tests ran the serial-shard binaries itself'
            % KILL_VAR)
        return None
    if mode == 'killswitch':
        raise StepFail('the mode file says killswitch but the kill switch is off')
    if mode == 'none':
        if present:
            raise StepFail('mode none but %s lists binaries' % TARGETS_FILE)
        say('no serial-shard binaries were deferred to this step')
        return None
    return temp, _read_targets(temp)


def run_step(host, env: dict) -> int:
    started = host.now()
    try:
        inputs = _step_inputs(env)
        if inputs is None:
            return 0
        temp, (shard, targets, residual) = inputs
        selection = [part for name in targets for part in ('--test', name)]
        secs = watchdog_secs(env, host.now())
        if secs <= 0:
            raise StepFail('no job time left for the serial shard step')
        timeout = host.which('timeout')
        if not timeout:
            raise StepFail('timeout is not on PATH')
        watchdog = [timeout, '--signal=TERM', KILL_AFTER, str(secs)]
        if env.get(FLAG_VAR) != '1':
            raise StepFail('the step env does not set %s=1' % FLAG_VAR)
        db = _shared_db(env)
        w = wrapper()
        tpl, run_id = w.template_name(db), w.new_run_id()
        for name in (LEDGER_FILE, RUN_FILE):
            if (temp / name).exists():
                raise StepFail('%s already exists: this leg ran the step before' % name)
        log_dir = shard / LOG_DIR
        if log_dir.exists() and any(log_dir.iterdir()):
            raise StepFail('the log directory already holds logs: %s' % log_dir)
    except StepFail as exc:
        fail(str(exc))
        return 1
    reasons: list[str] = []
    counts = {'isolated': 0, 'residual': 0}
    rows: list = []
    try:
        # SB: the run id is on disk before the first clone, so Cleanup finds it even without GITHUB_ENV.
        _write_atomic(temp / RUN_FILE, '%s=%s\n' % (RUN_ID_VAR, run_id))
        host.append_env('%s=%s' % (RUN_ID_VAR, run_id))
        host.append_env('%s=%s' % (TEMPLATE_VAR, tpl))
        reasons, counts, rows = _isolated(host, env, shard, targets, residual, selection, watchdog, db, tpl, run_id)
    except (StepCancelled, StepFail) as exc:
        reasons.append(str(exc))
    except OSError as exc:
        reasons.append('cannot write %s (%s)' % (RUN_FILE, type(exc).__name__))
    finally:
        reasons += _teardown(host, env, db, tpl, run_id)
        reasons += _redact_dir(log_dir)
    say('serial shard step wall time: %ds, jobs=%s, binaries=%d' % (int(host.now() - started), JOBS, len(targets)))
    if not reasons:
        text = ledger_text(rows, run_id)
        reasons = ledger_reasons(text, targets, run_id, residual, db)
        if not reasons:
            try:
                _write_atomic(temp / LEDGER_FILE, text)
            except OSError as exc:
                reasons.append('cannot write %s (%s)' % (LEDGER_FILE, type(exc).__name__))
    for reason in _capped(reasons):
        fail(reason)
    if reasons:
        return 1
    say('serial shard isolated binaries ok: binaries=%d isolated=%d residual=%d'
        % (len(targets), counts['isolated'], counts['residual']))
    return 0


def _isolated(host, env, shard, targets, residual, selection, watchdog, db, tpl, run_id):
    none = {'isolated': 0, 'residual': 0}
    rc = host.run(prebuild_argv(selection), env)
    if rc != 0:
        return ['prebuild failed (exit %d)' % rc], none, []
    rc, out = host.capture([sys.executable, str(WRAPPER), 'setup', '--db', db, '--jobs', JOBS,
                            '--run-id', run_id, '--emit-env'], env)
    if rc != 0:
        return ['wrapper setup failed (exit %d)' % rc], none, []
    emitted = dict(line.split('=', 1) for line in out.splitlines() if '=' in line)
    if TEMPLATE_VAR not in emitted:
        return ['setup emitted no %s' % TEMPLATE_VAR], none, []
    if emitted[TEMPLATE_VAR] != tpl:
        return ['setup template is not %s' % tpl], none, []
    if emitted.get(RUN_ID_VAR, run_id) != run_id:
        return ['setup run id is not %s' % run_id], none, []
    log_dir = shard / LOG_DIR
    argv = watchdog + [sys.executable, str(WRAPPER), 'run', '--targets-file', str(shard / TARGETS_FILE),
                       '--residual-file', str(shard / RESIDUAL_FILE), '--jobs', JOBS, '--log-dir', str(log_dir),
                       '--run-id', run_id] + TEST_ARGS + ['--', 'cargo', 'test', '--no-fail-fast'] + FEATURES
    rc = host.run(argv, _child_env(env, **{FLAG_VAR: '1', TEMPLATE_VAR: tpl, RUN_ID_VAR: run_id}))
    reasons = []
    if rc != 0:
        reasons.append('%s (exit %d)' % (WRAPPER_EXITS.get(rc, 'test failures'), rc))
    more, counts, rows = _log_reasons(host, env, log_dir, targets, residual, db, wrapper().run_prefix(run_id))
    return reasons + more, counts, rows


def cmd_leftovers(host, env: dict) -> int:
    try:
        run_id = env.get(RUN_ID_VAR, '')
        if not run_id and env.get(TEMP_VAR):
            run_id = _read_run_file(Path(env[TEMP_VAR])) or ''
        if not run_id:
            raise StepFail('no isolation run id (%s or %s)' % (RUN_ID_VAR, RUN_FILE))
        if not wrapper().valid_run_id(run_id):
            raise StepFail('%s is not a valid run id' % RUN_ID_VAR)
        db = _shared_db(env)
        clones, template = host.leftovers(env, db, run_id)
    except StepFail as exc:
        fail(str(exc))
        return 1
    say('isolation leftovers after teardown: clones=%d template=%d' % (clones, template))
    return 1 if clones or template else 0


def _cleanup_ledger(temp: Path, run_id: str, shared_db: str) -> tuple[list[str], int]:
    try:
        _shard, targets, residual = _read_targets(temp)
    except StepFail as exc:
        return [str(exc)], 0
    try:
        with (temp / LEDGER_FILE).open('rb') as handle:
            data = handle.read(LEDGER_MAX_BYTES + 1)
    except OSError:
        return ['cannot read %s: the isolated step did not complete' % LEDGER_FILE], len(targets)
    return ledger_reasons(data.decode('utf-8', 'replace'), targets, run_id, residual, shared_db), len(targets)


def cmd_cleanup(host, env: dict) -> int:
    """I-11 / SB: the always() Cleanup step tears this run down again, then proves the ledger is complete
    and nothing is left. A deferred leg without a run id is red; mode none / killswitch must have no
    deferred list, no run file and no ledger."""
    try:
        temp, mode = _mode(env)
        if mode != 'deferred':
            if _targets_present(temp):
                raise StepFail('mode %s but %s lists binaries' % (mode, TARGETS_FILE))
            if (temp / RUN_FILE).exists() or (temp / LEDGER_FILE).exists():
                raise StepFail('mode %s but %s or %s exists' % (mode, RUN_FILE, LEDGER_FILE))
            say('mode %s: this leg created no clones' % mode)
            return 0
        run_id = _read_run_file(temp)
        if run_id is None:
            raise StepFail('cannot read %s: the isolated step never started' % RUN_FILE)
        if env.get(RUN_ID_VAR) and env[RUN_ID_VAR] != run_id:
            raise StepFail('%s is not the run id in %s' % (RUN_ID_VAR, RUN_FILE))
        db = _shared_db(env)
        tpl = wrapper().template_name(db)
        if env.get(TEMPLATE_VAR) not in (None, '', tpl):
            raise StepFail('%s is not %s' % (TEMPLATE_VAR, tpl))
    except StepFail as exc:
        fail(str(exc))
        return 1
    reasons = _teardown(host, env, db, tpl, run_id)
    more, binaries = _cleanup_ledger(temp, run_id, db)
    reasons += more
    for reason in _capped(reasons):
        fail(reason)
    if reasons:
        return 1
    say('isolation ledger complete and no clone left: binaries=%d' % binaries)
    return 0


def cmd_killswitch(env: dict) -> int:
    try:
        print('on' if killswitch(env) else 'off', flush=True)
    except StepFail as exc:
        print(redact('%s FAIL: %s' % (TAG, exc)), file=sys.stderr, flush=True)
        return 1
    return 0


def _print_line(line: str) -> None:
    print(line, flush=True)


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
        """S5 / SB: only the run id and the template, with an identifier value; GITHUB_ENV unset is red."""
        if not ENV_LINE_RE.fullmatch(line):
            raise StepFail('refusing an env line of unexpected shape')
        target = os.environ.get('GITHUB_ENV', '')
        if not target:
            raise StepFail('GITHUB_ENV is not set: the run id cannot reach the Cleanup step')
        with Path(target).open('a', encoding='utf-8') as handle:
            handle.write(line + '\n')

    def capture(self, argv: list[str], env: dict) -> tuple[int, str]:
        done = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=SETUP_TIMEOUT_SECS,
                              errors='replace')
        for line in (done.stderr or '').splitlines():
            print(redact(line), file=sys.stderr, flush=True)
        return done.returncode, done.stdout or ''

    def run(self, argv: list[str], env: dict) -> int:
        """Run ``argv`` with its output streamed through ``redact_lines`` (SD); TERM on cancel."""
        child = subprocess.Popen(argv, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        with child.stdout:
            pump = threading.Thread(target=redact_lines, args=(child.stdout.readline, _print_line), daemon=True)
            pump.start()
            try:
                rc = child.wait()
            except StepCancelled:
                child.send_signal(signal.SIGTERM)
                try:
                    child.wait(timeout=TERM_WAIT_SECS)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
                raise
            finally:
                pump.join(timeout=PUMP_JOIN_SECS)
        return rc

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
    parser.add_argument('command', choices=('run', 'leftovers', 'cleanup', 'killswitch', 'redact-logs'))
    args = parser.parse_args(argv)
    env = dict(os.environ)
    if args.command == 'killswitch':
        return cmd_killswitch(env)
    if args.command == 'redact-logs':
        return cmd_redact_logs(env)
    host = Host()
    signal.signal(signal.SIGTERM, host.on_signal)
    signal.signal(signal.SIGINT, host.on_signal)
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
