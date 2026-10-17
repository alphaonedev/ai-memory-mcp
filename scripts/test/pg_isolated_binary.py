#!/usr/bin/env python3
"""Per-binary Postgres isolation for the enterprise-fed CI legs (#6383 / #6386).

OPT-IN. Nothing here runs unless ``AI_MEMORY_TEST_PG_ISOLATE=1`` is already in
the environment; ``.github/workflows/ci.yml`` never sets it on any leg, and
``CI_PG_ISOLATE_OFF=1`` overrides it (hard kill switch). Default-on, and
raising ``--test-threads`` above 1, wait for two green sharded carrier runs
and a 5-agent vote (4d3ea1c5).

With isolation on, every integration-test binary gets its own database cloned
from a never-connected template, so binaries can run side by side.

Sub-commands (``-h`` on each):

``setup``     check the LIVE connection budget (``max_connections`` minus
              reserved slots minus the sessions open right now) and create
              ``<db>_tpl`` (age + vector, ``IS_TEMPLATE true
              ALLOW_CONNECTIONS false``). ``--emit-env`` prints
              ``AI_MEMORY_TEST_PG_TEMPLATE=`` and ``AI_MEMORY_TEST_PG_RUN_ID=``
              lines for ``$GITHUB_ENV``. Fails closed.
``run``       run ``cargo test --no-fail-fast --test <bin>`` once per binary,
              each against its own clone (held by a keepalive session while in
              use), ``--jobs`` at a time (degraded to what the live budget
              allows), then the residual list one at a time on the shared
              database with the flag stripped. Output goes to one log file per
              binary under ``--log-dir``; a failing binary's tail is echoed.
              SIGTERM/SIGINT stop dispatch, signal every child group, drop the
              clones and exit 143.
``teardown``  drop THIS run's clones (``--run-id``) and the template.
``sweep``     ADMIN ONLY, never run by CI: drop idle clones of any run that
              are older than ``--older-than`` seconds (at least 600).

No drop ever uses the FORCE option: a database with a session (another run's
binary, or a held clone) cannot be dropped, so a race fails instead of
terminating someone else's work.

Connection details reach ``psql`` through libpq environment variables
(``PGHOST``, ``PGPASSWORD``, ...), never through argv. The URL comes from
``AI_MEMORY_TEST_POSTGRES_URL`` (``--url`` exists for local admin use).

Clone names are ``ai_memory_t_<run id>_<10-digit unix seconds>_<8 hex>``; the
run id is ``[a-z0-9]{1,20}``. The Rust helper (``tests/common/pg_isolate.rs``)
uses the same shape.

Exit codes: 0 success, 2 usage or wrapper error (fails closed), 3 a clone
could not be minted or held, 143 terminated, otherwise the worst exit code of
the cargo runs. Standard library only, Python 3.9+.
"""
import argparse
import os
import re
import signal
import socket
import subprocess
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Dict, IO, List, Optional, Set, Tuple
from urllib.parse import parse_qsl, unquote, urlsplit

URL_VAR = 'AI_MEMORY_TEST_POSTGRES_URL'
AGE_URL_VAR = 'AI_MEMORY_TEST_AGE_URL'
FLAG_VAR = 'AI_MEMORY_TEST_PG_ISOLATE'
TEMPLATE_VAR = 'AI_MEMORY_TEST_PG_TEMPLATE'
RUN_ID_VAR = 'AI_MEMORY_TEST_PG_RUN_ID'
KILL_VAR = 'CI_PG_ISOLATE_OFF'
ISOLATED_PREFIX = 'ai_memory_t'
TEMPLATE_SUFFIX = '_tpl'
ALREADY_EXISTS = 'already exists'  # psql detail of a CREATE DATABASE onto an occupied name
IDENT_MAX = 63
PSQL_SQL_ERROR = 1  # psql exit status for a refused statement; every other status leaves the outcome unknown
RUN_ID_MAX_LEN = 20
MAX_JOBS = 8
PER_BINARY_CONNECTIONS = 18
HOLD_CONNECTIONS = 1
CONNECTION_HEADROOM = 20
MINT_ATTEMPTS = 3
MINT_RETRY_PAUSE = 0.5
DROP_ATTEMPTS = 10
DROP_RETRY_PAUSE = 1.0
HOLD_WAIT_SECS = 15.0
HOLD_POLL_SECS = 0.2
MIN_SWEEP_AGE_SECS = 600
TERM_GRACE_SECS = 5.0
LOG_TAIL_LINES = 200
CONNECT_TIMEOUT_SECS = '30'
# decision: one psql call (CREATE ... TEMPLATE copies a database, DROP waits on sessions) gets 300 s, well above
# any healthy statement, so only a stalled server or a held lock trips it (#7429).
PSQL_TIMEOUT_SECS = 300.0
# decision: the server cancels its own statement over Popen+SIGINT, because a server-side cap still fires when
# psql is killed, hung or cut off, while a cancel request needs a live client (#7447). The cap is applied by a
# first `DO` statement in the same psql session (set_config, session level) and NOT through PGOPTIONS, because
# the server then reads every caller value itself (case, units, hex, octal, fractions, role- and database-level
# defaults) and the cap is the least non-zero of that value and ours: nothing is parsed here that the server
# could read differently (#7454, #7477, #7478, #7479, #7484). The statement cap is the client wall time minus
# the whole connect budget (see _connect_budget_secs) minus a fixed margin, so it fires before the client
# kill; lock_timeout is clamped a fixed gap below the effective statement_timeout (#7453, #7480).
PSQL_CAP_MARGIN_SECS = 10.0
PSQL_LOCK_GAP_SECS = 5.0
LIBPQ_MIN_CONNECT_SECS = 2
_DIGITS_RE = re.compile(r'[0-9]+')
IN_USE_TEXT = 'being accessed by other users'
EXIT_USAGE = 2
EXIT_MINT = 3
EXIT_TERM = 143

# URL query keys and the libpq variable each maps to. Anything else fails
# closed rather than being silently dropped.
_QUERY_TO_ENV = {
    'sslmode': 'PGSSLMODE',
    'sslrootcert': 'PGSSLROOTCERT',
    'sslcert': 'PGSSLCERT',
    'sslkey': 'PGSSLKEY',
    'sslcrl': 'PGSSLCRL',
    'connect_timeout': 'PGCONNECT_TIMEOUT',
    'application_name': 'PGAPPNAME',
    'target_session_attrs': 'PGTARGETSESSIONATTRS',
    'options': 'PGOPTIONS',
}
_RUN_ID_RE = re.compile(r'^[a-z0-9]{1,%d}$' % RUN_ID_MAX_LEN)
_ANY_NAME_RE = re.compile(r'^%s_([a-z0-9]{1,%d})_([0-9]{10})_([0-9a-f]{8})$' % (ISOLATED_PREFIX, RUN_ID_MAX_LEN))
_IDENT_RE = re.compile(r'^[A-Za-z0-9_]{1,%d}$' % IDENT_MAX)
_TARGET_RE = re.compile(r'^--(test|bin) ([A-Za-z0-9_-]+)$')
_PRINT_LOCK = threading.Lock()


class WrapperError(Exception):
    """A condition under which the wrapper refuses to continue (fail closed).

    ``returncode`` is the psql exit status when the error came from psql, else None."""

    def __init__(self, message: str, returncode: Optional[int] = None) -> None:
        super().__init__(message)
        self.returncode = returncode


def _out(line: str) -> None:
    """One line to stdout (CI log)."""
    with _PRINT_LOCK:
        print(line, flush=True)


def _emit(line: str) -> None:
    """One ``KEY=value`` line for ``$GITHUB_ENV`` (stdout, nothing else)."""
    print(line, flush=True)


def log(msg: str) -> None:
    """Diagnostics go to stderr so ``--emit-env`` stdout stays clean."""
    with _PRINT_LOCK:
        print('[pg_isolated_binary] ' + msg, file=sys.stderr, flush=True)


# --- names and URLs -------------------------------------------------------

def database_name(url: str) -> str:
    """Database segment of a postgres URL, query string ignored."""
    base = url.split('?', 1)[0].rstrip('/')
    return base.rsplit('/', 1)[-1]


def with_database(url: str, db: str) -> str:
    """Swap the database name, preserving the query string (TLS settings)."""
    base, sep, query = url.partition('?')
    base = base.rstrip('/')
    head = base.rsplit('/', 1)[0]
    return head + '/' + db + (sep + query if sep and query else '')


def quote_ident(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def valid_run_id(run_id: str) -> bool:
    return bool(_RUN_ID_RE.match(run_id or ''))


def new_run_id() -> str:
    return 'r' + uuid.uuid4().hex[:11]


def checked_run_id(run_id: Optional[str]) -> str:
    if not run_id or not valid_run_id(run_id):
        raise WrapperError('run id %r must match [a-z0-9]{1,%d}' % (run_id, RUN_ID_MAX_LEN))
    return run_id


def isolated_db_name(run_id: str, now: Optional[int] = None) -> str:
    checked_run_id(run_id)
    stamp = int(time.time()) if now is None else int(now)
    return '%s_%s_%010d_%s' % (ISOLATED_PREFIX, run_id, stamp, uuid.uuid4().hex[:8])


def parse_isolated_name(name: str, run_id: Optional[str] = None) -> Optional[int]:
    """Creation time of a clone name; with ``run_id`` only that run's clones."""
    found = _ANY_NAME_RE.match(name or '')
    if not found:
        return None
    if run_id is not None and found.group(1) != run_id:
        return None
    return int(found.group(2))


def run_prefix(run_id: str) -> str:
    return '%s_%s_' % (ISOLATED_PREFIX, checked_run_id(run_id))


def parse_target_line(line: str) -> List[str]:
    """``--test foo`` or ``--bin foo`` only; anything else is refused."""
    found = _TARGET_RE.match(line.strip())
    if not found:
        raise WrapperError('refusing target selector %r' % line)
    return ['--' + found.group(1), found.group(2)]


def template_name(db_name: str) -> str:
    """``<db>_tpl``. A name too long to take the suffix is refused, never
    truncated: truncation maps two different names onto one template (#7127)."""
    size = len(db_name.encode('utf-8'))
    if size + len(TEMPLATE_SUFFIX) > IDENT_MAX:
        raise WrapperError('database name %r is %d bytes; with %s the template name would exceed the %d-byte '
                           'identifier limit and be truncated onto another template'
                           % (db_name, size, TEMPLATE_SUFFIX, IDENT_MAX))
    return db_name + TEMPLATE_SUFFIX


def _checked_ident(name: str) -> str:
    if not _IDENT_RE.match(name or ''):
        raise WrapperError('unsafe database name %r' % name)
    return name


# --- connection budget ----------------------------------------------------

def clamp_jobs(jobs: int) -> int:
    if jobs < 1:
        raise WrapperError('--jobs must be at least 1, got %d' % jobs)
    return min(jobs, MAX_JOBS)


def required_connections(jobs: int) -> int:
    return jobs * (PER_BINARY_CONNECTIONS + HOLD_CONNECTIONS) + CONNECTION_HEADROOM


def width_for(available: int, jobs: int) -> int:
    """Parallel width that fits ``available`` free slots; fails closed at 0."""
    fits = (available - CONNECTION_HEADROOM) // (PER_BINARY_CONNECTIONS + HOLD_CONNECTIONS)
    width = min(clamp_jobs(jobs), fits)
    if width < 1:
        raise WrapperError('only %d free connection slot(s); one isolated binary needs %d'
                           % (available, required_connections(1)))
    return width


# --- psql through libpq env ------------------------------------------------

def libpq_env(url: str) -> Dict[str, str]:
    """Map a postgres URL to libpq environment variables (fails closed)."""
    parts = urlsplit(url)
    if parts.scheme not in ('postgres', 'postgresql'):
        raise WrapperError('not a postgres URL (scheme %r)' % parts.scheme)
    netloc = parts.netloc.rsplit('@', 1)[-1]
    if ',' in netloc:
        raise WrapperError('multi-host URLs are not supported')
    db = unquote(parts.path.lstrip('/'))
    if not db:
        raise WrapperError('the URL names no database')
    try:
        port = parts.port
    except ValueError as exc:
        raise WrapperError('bad port in the URL: %s' % exc)
    env = {'PGDATABASE': db, 'PGCONNECT_TIMEOUT': CONNECT_TIMEOUT_SECS}
    if parts.hostname:
        env['PGHOST'] = parts.hostname
    if port is not None:
        env['PGPORT'] = str(port)
    if parts.username:
        env['PGUSER'] = unquote(parts.username)
    if parts.password is not None:
        env['PGPASSWORD'] = unquote(parts.password)
    for key, value in parse_qsl(parts.query, keep_blank_values=True):
        var = _QUERY_TO_ENV.get(key)
        if var is None:
            raise WrapperError('unsupported URL query key %r' % key)
        if key == 'options' and (len(value) - len(value.rstrip('\\'))) % 2:
            raise WrapperError('the URL query key \'options\' ends in an unescaped backslash; end it with a '
                               'value character or double the backslash')
        env[var] = value
    return env


def _pg_env(url: str) -> Dict[str, str]:
    """The process env with inherited PG* removed and this URL's libpq vars."""
    env = {k: v for k, v in os.environ.items() if not k.startswith('PG')}
    env.update(libpq_env(url))
    return env


def _connect_budget_secs(env: Dict[str, str]) -> int:
    """Worst-case seconds libpq may spend connecting: connect_timeout (floored at 2 s) per resolved address,
    doubled when sslmode may retry without TLS (#7482). Raises on a value that is not a plain positive number."""
    connect = env.get('PGCONNECT_TIMEOUT', '')
    if _DIGITS_RE.fullmatch(connect) is None or int(connect) <= 0:
        raise WrapperError('connect_timeout %r must be a positive whole number of seconds so the server-side '
                           'statement cap can be sized under the psql limit' % connect)
    host = env.get('PGHOST', '')
    if env.get('PGHOSTADDR') or not host or host.startswith('/'):
        return max(int(connect), LIBPQ_MIN_CONNECT_SECS)
    try:
        port = int(env.get('PGPORT') or 5432)
        addresses = len({info[4] for info in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)}) or 1
    except (OSError, ValueError):
        addresses = 1
    tries = 2 if env.get('PGSSLMODE', 'prefer') in ('prefer', 'allow') else 1
    return max(int(connect), LIBPQ_MIN_CONNECT_SECS) * addresses * tries


def server_caps_sql(env: Dict[str, str]) -> str:
    """A ``DO`` statement setting session statement_timeout and lock_timeout to the least non-zero of the
    value the server already resolved for this session (startup options, role and database defaults) and the
    wrapper cap; lock_timeout is clamped a gap below the effective statement_timeout (#7453, #7480, #7484)."""
    cap_ms = int((PSQL_TIMEOUT_SECS - _connect_budget_secs(env) - PSQL_CAP_MARGIN_SECS) * 1000)
    gap_ms = int(PSQL_LOCK_GAP_SECS * 1000)
    lock_cap_ms = cap_ms - gap_ms
    if lock_cap_ms <= 0:
        raise WrapperError('the connect budget leaves no room for a server-side statement cap under the %g s '
                           'psql limit' % PSQL_TIMEOUT_SECS)
    return (
        "DO $cap$ DECLARE s bigint; l bigint; BEGIN "
        "SELECT setting::bigint INTO s FROM pg_settings WHERE name = 'statement_timeout'; "
        "SELECT setting::bigint INTO l FROM pg_settings WHERE name = 'lock_timeout'; "
        "IF s = 0 OR s > %(cap)d THEN s := %(cap)d; END IF; "
        "IF l = 0 OR l > %(lock)d THEN l := %(lock)d; END IF; "
        "IF l >= s THEN l := greatest(s - %(gap)d, 1); END IF; "
        "PERFORM set_config('statement_timeout', s::text || 'ms', false); "
        "PERFORM set_config('lock_timeout', l::text || 'ms', false); "
        "END $cap$" % {'cap': cap_ms, 'lock': lock_cap_ms, 'gap': gap_ms})


def psql(url: str, sql: str, tuples: bool = False) -> str:
    """Run one statement through psql; returns stdout, raises on failure."""
    argv = ['psql', '-X', '-q', '-v', 'ON_ERROR_STOP=1']
    if tuples:
        argv.append('-At')
    env = _pg_env(url)
    # One statement per call: the server cap bounds each statement, not the whole -c string (#7481).
    argv += ['-c', server_caps_sql(env), '-c', sql]
    try:
        done = subprocess.run(argv, capture_output=True, text=True, env=env, timeout=PSQL_TIMEOUT_SECS)
    except subprocess.TimeoutExpired:
        raise WrapperError('psql timed out after %g s' % PSQL_TIMEOUT_SECS, None)
    if done.returncode != 0:
        raise WrapperError('psql failed (%d): %s' % (done.returncode, (done.stderr or '').strip() or 'no stderr'),
                           done.returncode)
    return done.stdout or ''


def connection_budget(url: str) -> Tuple[int, int, int, int]:
    """``(max_connections, reserved, sessions_now, available)`` from the server."""
    sql = ("SELECT current_setting('max_connections')::int, "
           "current_setting('superuser_reserved_connections')::int, "
           "coalesce(current_setting('reserved_connections', true)::int, 0), "
           "(SELECT count(*) FROM pg_stat_activity)")
    raw = psql(url, sql, tuples=True).strip()
    fields = raw.split('|')
    if len(fields) != 4 or not all(f.strip().isdigit() for f in fields):
        raise WrapperError('could not read the connection budget (got %r)' % raw)
    most, su_reserved, reserved, now = (int(f) for f in fields)
    reserved_total = su_reserved + reserved
    return most, reserved_total, now, most - reserved_total - now


# --- clones ---------------------------------------------------------------

def mint(base_url: str, tpl: str, run_id: str, now: Optional[int] = None) -> Tuple[str, str]:
    """CREATE DATABASE ... TEMPLATE; retry while the template reports in-use."""
    name = isolated_db_name(run_id, now)
    sql = 'CREATE DATABASE %s TEMPLATE %s' % (quote_ident(name), quote_ident(_checked_ident(tpl)))
    last = ''
    for attempt in range(1, MINT_ATTEMPTS + 1):
        try:
            psql(base_url, sql)
            return with_database(base_url, name), name
        except WrapperError as exc:
            last = str(exc)
            if IN_USE_TEXT not in last or attempt == MINT_ATTEMPTS:
                break
            time.sleep(MINT_RETRY_PAUSE * attempt)
    raise WrapperError('could not mint %s from %s: %s' % (name, tpl, last))


def drop(admin_url: str, name: str, run_id: Optional[str], attempts: int = DROP_ATTEMPTS) -> None:
    """Drop one clone WITHOUT force. ``run_id`` scopes it to that run's clones
    (``None`` only for the admin sweep). A clone that still has a session is
    retried while the session drains, then the drop fails."""
    if parse_isolated_name(name, run_id) is None:
        raise WrapperError('refusing to drop %r: not a clone of run %r' % (name, run_id))
    sql = 'DROP DATABASE IF EXISTS %s' % quote_ident(name)
    for attempt in range(1, attempts + 1):
        try:
            psql(admin_url, sql)
            return
        except WrapperError as exc:
            if IN_USE_TEXT not in str(exc) or attempt == attempts:
                raise
            time.sleep(DROP_RETRY_PAUSE)


def session_count(admin_url: str, name: str) -> int:
    raw = psql(admin_url, "SELECT count(*) FROM pg_stat_activity WHERE datname = '%s'"
               % _checked_ident(name), tuples=True).strip()
    return int(raw) if raw.isdigit() else 0


def open_hold(clone_url: str) -> 'subprocess.Popen[str]':
    """A keepalive psql session on the clone: while it lives, no sweep can drop
    the clone. It waits on stdin; closing stdin ends it.

    It runs no statement and its whole life is the clone guard, so it deliberately gets NO server-side
    statement_timeout or lock_timeout (it never goes through ``psql()``): a cap would only end the guard early
    (#7456)."""
    return subprocess.Popen(['psql', '-X', '-q', '-v', 'ON_ERROR_STOP=1'], stdin=subprocess.PIPE,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            env=_pg_env(clone_url), text=True)


def wait_for_hold(admin_url: str, name: str, hold: 'subprocess.Popen[str]') -> None:
    deadline = time.monotonic() + HOLD_WAIT_SECS
    while True:
        if hold.poll() is not None:
            raise WrapperError('the keepalive session on %s exited (%s)' % (name, hold.returncode))
        if session_count(admin_url, name) >= 1:
            return
        if time.monotonic() >= deadline:
            raise WrapperError('no keepalive session on %s after %.0fs' % (name, HOLD_WAIT_SECS))
        time.sleep(HOLD_POLL_SECS)


def close_hold(hold: Optional['subprocess.Popen[str]']) -> None:
    if hold is None:
        return
    try:
        if hold.stdin:
            hold.stdin.close()
        hold.wait(timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        hold.kill()
        hold.wait()


# --- tier steps -----------------------------------------------------------

def _proved_absent(url: str, check: str) -> Tuple[bool, str]:
    """``(absent, reason)``: absent only when the read-only check succeeds with no row (#7405, #7427)."""
    try:
        found = psql(url, check, tuples=True).strip()
    except WrapperError as exc:
        return False, 'the existence check itself failed: %s' % exc
    if found:
        return False, 'the existence check found a database with this name'
    return True, ''


def setup(url: str, db_name: str, jobs: int = MAX_JOBS) -> str:
    """Check the live budget, then create the locked template. Returns its name."""
    _checked_ident(db_name)
    tpl = _checked_ident(template_name(db_name))
    need = required_connections(clamp_jobs(jobs))
    most, reserved, now, available = connection_budget(url)
    if available < need:
        raise WrapperError('only %d free connection slots (max_connections=%d, reserved=%d, open now=%d); '
                           '%d needed for %d parallel binaries' % (available, most, reserved, now, need, jobs))
    q = quote_ident(tpl)
    # Ownership comes only from a successful CREATE. An occupied name (a foreign
    # or leftover template) or a missing privilege refuses: this function never
    # ALTERs or DROPs a database it did not create (#7127).
    try:
        psql(url, 'CREATE DATABASE %s' % q)
    except WrapperError as exc:
        if ALREADY_EXISTS in str(exc):
            raise WrapperError('refusing to use template %s, it was not created by this run: %s; if it is a '
                               'leftover of your own earlier run, run `pg_isolated_binary.py teardown --db %s '
                               '--run-id <run id>` first, otherwise choose a different --db'
                               % (tpl, exc, db_name))
        check = "SELECT 1 FROM pg_database WHERE datname = '%s'" % tpl.replace("'", "''")
        if exc.returncode is None:
            why = 'psql timed out, so the server may still commit the statement'
        else:
            why = 'psql ended with status %s, not a plain SQL error' % exc.returncode
        absent = False
        if exc.returncode == PSQL_SQL_ERROR:
            absent, why = _proved_absent(url, check)
        if not absent:
            # Status 1 means refused only when the existence check run just above succeeds with no row. A row, a
            # failed check or any other status (2 lost connection, a negative signal status such as -9, None, an
            # unexpected code) may follow a committed CREATE, so the outcome is unknown: setup neither claims the
            # template nor DROPs it (#7388, #7400, #7427, #7428).
            raise WrapperError('CREATE DATABASE %s ended without a clean answer; the outcome is unknown and the '
                               'template may exist with no owner record: %s; %s; to check by hand run `%s` and, if '
                               'the template is from this run, run `pg_isolated_binary.py teardown --db %s '
                               '--run-id <run id>`'
                               % (tpl, exc, why, check, db_name), exc.returncode)
        raise WrapperError('CREATE DATABASE %s was refused; nothing was created or changed: %s' % (tpl, exc))
    try:
        psql(with_database(url, tpl), 'CREATE EXTENSION IF NOT EXISTS age')
        psql(with_database(url, tpl), 'CREATE EXTENSION IF NOT EXISTS vector')
        psql(url, 'ALTER DATABASE %s WITH IS_TEMPLATE true ALLOW_CONNECTIONS false' % q)
    except BaseException:
        # The template is ours now and nothing else will drop it: plain DROP,
        # never FORCE; the primary error stays the one raised.
        try:
            psql(url, 'DROP DATABASE IF EXISTS %s' % q)
        except WrapperError as cleanup:
            log('WARN could not drop the half-built template %s: %s' % (tpl, cleanup))
        raise
    log('template %s ready (%d free connection slots, need %d)' % (tpl, available, need))
    return tpl


def _names(url: str, sql: str) -> List[str]:
    return [n for n in psql(url, sql, tuples=True).split() if _IDENT_RE.match(n)]


def teardown(url: str, db_name: str, run_id: str) -> int:
    """Drop this run's clones, then the template. Returns how many drops failed."""
    _checked_ident(db_name)
    prefix = run_prefix(run_id)
    tpl = _checked_ident(template_name(db_name))
    failed = 0
    names = [n for n in _names(url, "SELECT datname FROM pg_database WHERE starts_with(datname, '%s')" % prefix)
             if parse_isolated_name(n, run_id) is not None]
    for name in names:
        try:
            drop(url, name, run_id)
        except WrapperError as exc:
            failed += 1
            log('WARN could not drop %s: %s' % (name, exc))
    q = quote_ident(tpl)
    try:
        psql(url, 'ALTER DATABASE %s WITH IS_TEMPLATE false' % q)
    except WrapperError:
        pass  # already gone
    try:
        psql(url, 'DROP DATABASE IF EXISTS %s' % q)
    except WrapperError as exc:
        failed += 1
        log('WARN could not drop the template %s: %s' % (tpl, exc))
    log('teardown of run %s: %d clone(s) and template %s, %d failure(s)' % (run_id, len(names), tpl, failed))
    return failed


def sweep(url: str, older_than: int) -> List[str]:
    """ADMIN ONLY: drop idle clones of any run older than ``older_than`` s."""
    if older_than < MIN_SWEEP_AGE_SECS:
        raise WrapperError('--older-than must be at least %d seconds' % MIN_SWEEP_AGE_SECS)
    now_raw = psql(url, 'SELECT extract(epoch FROM now())::bigint', tuples=True).strip()
    if not now_raw.isdigit():
        raise WrapperError('could not read the server clock (got %r)' % now_raw)
    now = int(now_raw)
    listing = ("SELECT d.datname FROM pg_database d WHERE starts_with(d.datname, '%s_') "
               "AND NOT EXISTS (SELECT 1 FROM pg_stat_activity a WHERE a.datname = d.datname)"
               % ISOLATED_PREFIX)
    dropped = []
    for name in _names(url, listing):
        created = parse_isolated_name(name)
        if created is None or now - created < older_than:
            continue
        try:
            drop(url, name, None, attempts=1)
            dropped.append(name)
        except WrapperError as exc:
            log('WARN could not sweep %s: %s' % (name, exc))
    log('admin sweep dropped %d clone(s) older than %ds' % (len(dropped), older_than))
    return dropped


# --- the pool -------------------------------------------------------------

def _worst(codes: List[int]) -> int:
    norm = [c if c >= 0 else 128 - c for c in codes]
    return max(norm) if norm else 0


def _tail(path: Path, lines: int) -> List[str]:
    try:
        with path.open(encoding='utf-8', errors='replace') as handle:
            return handle.read().splitlines()[-lines:]
    except OSError as exc:
        return ['(could not read %s: %s)' % (path, exc)]


class Runner:
    """Runs binaries against held clones; ``terminate`` stops everything."""

    def __init__(self, cargo: List[str], test_args: List[str], env: Dict[str, str], tpl: str,
                 run_id: str, admin: str, log_dir: str, width: int) -> None:
        self.cargo = list(cargo)
        self.test_args = list(test_args)
        self.env = dict(env)
        self.tpl = tpl
        self.run_id = checked_run_id(run_id)
        self.admin = admin
        self.log_dir = Path(log_dir)
        self.width = clamp_jobs(width)
        self.stop = threading.Event()
        self._lock = threading.Lock()
        self._children: Dict[int, 'subprocess.Popen[str]'] = {}
        self._killer: Optional[threading.Timer] = None

    def terminate(self) -> None:
        """Stop dispatching, TERM every child group, KILL after a grace."""
        self.stop.set()
        self._signal_children(signal.SIGTERM)
        with self._lock:
            if self._killer is None:
                self._killer = threading.Timer(TERM_GRACE_SECS, self._signal_children, (signal.SIGKILL,))
                self._killer.daemon = True
                self._killer.start()

    def _signal_children(self, sig: int) -> None:
        with self._lock:
            pids = list(self._children)
        for pid in pids:
            try:
                os.killpg(pid, sig)
            except (ProcessLookupError, PermissionError):
                pass

    def _spawn(self, argv: List[str], env: Dict[str, str], out: IO[str]) -> 'subprocess.Popen[str]':
        with self._lock:
            child = subprocess.Popen(argv, env=env, stdout=out, stderr=subprocess.STDOUT,
                                     start_new_session=True, text=True)
            self._children[child.pid] = child
        if self.stop.is_set():
            self._signal_children(signal.SIGTERM)
        return child

    def _forget(self, child: 'subprocess.Popen[str]') -> None:
        with self._lock:
            self._children.pop(child.pid, None)

    def _report(self, label: str, rc: int, log_path: Path) -> None:
        if rc == 0:
            results = [ln for ln in _tail(log_path, 10_000) if 'test result:' in ln]
            _out('[pg_isolated_binary] PASS %s (log %s)' % (label, log_path))
            for line in results:
                _out('  ' + line)
            return
        _out('::group::FAIL %s (exit %d), last %d lines of %s' % (label, rc, LOG_TAIL_LINES, log_path))
        for line in _tail(log_path, LOG_TAIL_LINES):
            _out(line)
        _out('::endgroup::')

    def run_one(self, target: List[str], isolate: bool = True) -> int:
        """One binary: mint + hold a clone, cargo test it, release, drop."""
        label = target[-1]
        if self.stop.is_set():
            return EXIT_TERM
        argv = self.cargo + list(target)
        if self.test_args:
            argv += ['--'] + self.test_args
        child_env = dict(self.env)
        minted: Optional[str] = None
        hold = None
        try:
            if isolate:
                url, minted = mint(self.admin, self.tpl, self.run_id)
                hold = open_hold(url)
                wait_for_hold(self.admin, minted, hold)
                child_env[URL_VAR] = url
                if self.env.get(AGE_URL_VAR):
                    child_env[AGE_URL_VAR] = with_database(self.env[AGE_URL_VAR], minted)
                log('%s -> %s' % (label, minted))
            else:
                # Residual binaries stay on the shared database: strip the flag
                # so the Rust helper does not mint a clone of its own.
                child_env.pop(FLAG_VAR, None)
            if self.stop.is_set():
                return EXIT_TERM
            self.log_dir.mkdir(parents=True, exist_ok=True)
            log_path = self.log_dir / (label + '.log')
            with log_path.open('w', encoding='utf-8') as out:
                child = self._spawn(argv, child_env, out)
                try:
                    rc = child.wait()
                finally:
                    self._forget(child)
            if self.stop.is_set():
                return EXIT_TERM
            self._report(label, rc, log_path)
            return rc
        except (WrapperError, OSError) as exc:
            log('FAIL %s: %s' % (label, exc))
            return EXIT_MINT
        finally:
            close_hold(hold)
            if minted:
                try:
                    drop(self.admin, minted, self.run_id)
                except WrapperError as exc:
                    log('WARN could not drop %s (teardown reclaims it): %s' % (minted, exc))

    def run_all(self, targets: List[List[str]], residual: Set[str]) -> int:
        """Pool the isolated binaries, then run the residual list serially."""
        if not targets:
            raise WrapperError('no targets to run')
        pooled = [t for t in targets if t[-1] not in residual]
        serial = [t for t in targets if t[-1] in residual]
        codes: List[int] = []
        if pooled:
            with ThreadPoolExecutor(max_workers=self.width) as pool:
                futures = [pool.submit(self.run_one, t, True) for t in pooled]
                codes += [f.result() for f in futures]
        for target in serial:
            if self.stop.is_set():
                break
            codes.append(self.run_one(target, isolate=False))
        if self.stop.is_set():
            return EXIT_TERM
        return _worst(codes)


# --- CLI ------------------------------------------------------------------

def read_lines(path: str) -> List[str]:
    with open(path, encoding='utf-8') as handle:
        return [ln.strip() for ln in handle if ln.strip() and not ln.lstrip().startswith('#')]


def _url(args: argparse.Namespace) -> str:
    url = getattr(args, 'url', None) or os.environ.get(URL_VAR)
    if not url:
        raise WrapperError('set %s (or pass --url for local admin use)' % URL_VAR)
    return url


def _default_log_dir() -> str:
    runner_temp = os.environ.get('RUNNER_TEMP')
    if runner_temp:
        return str(Path(runner_temp) / 'pg-isolate-logs')
    return str(Path(__file__).resolve().parents[2] / '.local-runs' / 'pg-isolate-logs')


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.split('\n', 1)[0])
    sub = parser.add_subparsers(dest='cmd', required=True)
    url_help = 'admin URL for local use (default and CI: $%s; argv is visible to other users)' % URL_VAR

    setup_p = sub.add_parser('setup', help='check the live budget and create the template')
    setup_p.add_argument('--url', help=url_help)
    setup_p.add_argument('--db', help='base database (default: the URL database)')
    setup_p.add_argument('--jobs', type=int, default=MAX_JOBS)
    setup_p.add_argument('--run-id', help='run id for the clone names (default: generated)')
    setup_p.add_argument('--emit-env', action='store_true',
                         help='print %s= and %s= lines for $GITHUB_ENV' % (TEMPLATE_VAR, RUN_ID_VAR))

    down = sub.add_parser('teardown', help="drop this run's clones and the template")
    down.add_argument('--url', help=url_help)
    down.add_argument('--db', help='base database (default: the URL database)')
    down.add_argument('--run-id', help='the run whose clones are dropped (default: $%s)' % RUN_ID_VAR)

    sweep_p = sub.add_parser('sweep', help='ADMIN ONLY: drop idle clones of any run older than N s')
    sweep_p.add_argument('--url', help=url_help)
    sweep_p.add_argument('--older-than', type=int, required=True,
                         help='minimum age in seconds (at least %d)' % MIN_SWEEP_AGE_SECS)

    run = sub.add_parser('run', help='run each binary against its own clone')
    run.add_argument('--url', help=url_help)
    run.add_argument('--run-id', help='run id (default: $%s)' % RUN_ID_VAR)
    run.add_argument('--template', help='template database (default: $%s)' % TEMPLATE_VAR)
    run.add_argument('--log-dir', help='per-binary log files (default: $RUNNER_TEMP/pg-isolate-logs '
                                       'or .local-runs/pg-isolate-logs)')
    run.add_argument('--jobs', type=int, default=MAX_JOBS)
    run.add_argument('--targets-file', required=True, help='one "--test NAME" / "--bin NAME" per line')
    run.add_argument('--residual-file', help='names that stay serial on the shared database')
    run.add_argument('--test-arg', action='append', default=[], help='forwarded after "--" to libtest')
    run.add_argument('cargo', nargs=argparse.REMAINDER, help='-- cargo test --no-fail-fast [features]')
    return parser


def _cmd_run(args: argparse.Namespace, url: str) -> int:
    if os.environ.get(FLAG_VAR) != '1':
        raise WrapperError('isolation is opt-in: %s=1 is not set' % FLAG_VAR)
    if os.environ.get(KILL_VAR) == '1':
        raise WrapperError('isolation is switched off by %s=1' % KILL_VAR)
    cargo = args.cargo[1:] if args.cargo[:1] == ['--'] else args.cargo
    if not cargo:
        raise WrapperError('missing the cargo command after "--"')
    tpl = _checked_ident(args.template or os.environ.get(TEMPLATE_VAR) or '')
    run_id = checked_run_id(args.run_id or os.environ.get(RUN_ID_VAR))
    targets = [parse_target_line(ln) for ln in read_lines(args.targets_file)]
    residual = set(read_lines(args.residual_file)) if args.residual_file else set()
    available = connection_budget(url)[3]
    width = width_for(available, args.jobs)
    if width < clamp_jobs(args.jobs):
        log('::warning::only %d free connection slots: width degraded to %d' % (available, width))
    env = dict(os.environ)
    env[URL_VAR] = url
    runner = Runner(cargo, args.test_arg, env, tpl, run_id, url, args.log_dir or _default_log_dir(), width)

    def on_signal(signum: int, _frame: object) -> None:
        log('signal %d: stopping dispatch, terminating children, dropping clones' % signum)
        runner.terminate()
    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)
    return runner.run_all(targets, residual)


def main(argv: Optional[List[str]] = None) -> int:
    try:
        args = build_parser().parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else EXIT_USAGE
    try:
        url = _url(args)
        if args.cmd == 'setup':
            db = args.db or database_name(url)
            run_id = checked_run_id(args.run_id or new_run_id())
            tpl = setup(url, db, args.jobs)
            if args.emit_env:
                _emit('%s=%s' % (TEMPLATE_VAR, tpl))
                _emit('%s=%s' % (RUN_ID_VAR, run_id))
            return 0
        if args.cmd == 'teardown':
            db = args.db or database_name(url)
            teardown(url, db, checked_run_id(args.run_id or os.environ.get(RUN_ID_VAR)))
            return 0
        if args.cmd == 'sweep':
            sweep(url, args.older_than)
            return 0
        return _cmd_run(args, url)
    except WrapperError as exc:
        print('pg_isolated_binary: %s' % exc, file=sys.stderr)
        return EXIT_USAGE


if __name__ == '__main__':
    sys.exit(main())
