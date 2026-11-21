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

``setup``     refuse a base ``--db`` that is not an ephemeral CI base
              (``ai_memory_test_ci_<run>_<attempt>_<leg>``: run 1-20 digits,
              attempt 1-5 digits, leg 1-36 of ``[a-z0-9_]``) unless
              ``--allow-shared-base "<reason>"`` names why a shared base is safe
              (the URL default is a shared base; no base is ever created here),
              refuse a base whose ``lineage_integrity_watermark.high_water`` is
              above ``count(*)`` of ``agent_lineage`` in any schema (#6983; a
              row the precheck cannot read is a refusal too), check the LIVE
              connection budget (``max_connections`` minus reserved slots minus
              the sessions open right now) and create ``<db>_tpl`` (age +
              vector, ``IS_TEMPLATE true ALLOW_CONNECTIONS false``).
              ``--emit-env`` prints ``AI_MEMORY_TEST_PG_TEMPLATE=`` and
              ``AI_MEMORY_TEST_PG_RUN_ID=`` lines for ``$GITHUB_ENV``. Fails
              closed. One ownership guard holds every name this run CREATEd:
              any exception, and SIGTERM / SIGINT / SIGHUP in any window, drop
              exactly those names (plain DROP, never FORCE) before the exit.
``run``       run ``cargo test --no-fail-fast --test <bin>`` once per binary,
              each against its own clone (held by a keepalive session while in
              use), ``--jobs`` at a time (degraded to what the live budget
              allows), then the residual list one at a time on the shared
              database with the flag stripped. Output goes to one log file per
              binary under ``--log-dir``; a failing binary's tail is echoed.
              SIGTERM/SIGINT stop dispatch, signal every child group, drop the
              clones and exit 143.
``teardown``  drop THIS run's clones (``--run-id``) and the template. The
              ``--db`` is classified as in setup, and a teardown is refused
              unless ``AI_MEMORY_TEST_PG_TEMPLATE`` is set to the template
              setup emitted for that ``--db`` (unset or empty is refused, #7031).
              A signal or an error does not stop it: every drop is still tried.
``sweep``     ADMIN ONLY, never run by CI: drop idle clones of any run that
              are older than ``--older-than`` seconds (at least 600).

No drop ever uses the FORCE option: a database with a session (another run's
binary, or a held clone) cannot be dropped, so a race fails instead of
terminating someone else's work.

Connection details reach ``psql`` through libpq environment variables
(``PGHOST``, ``PGPASSWORD``, ...), never through argv. The URL comes from
``AI_MEMORY_TEST_POSTGRES_URL`` (``--url`` exists for local admin use). Every refusal about the URL is a fixed
text that never contains the URL or any part of it (#9689); setup's ``--db``
and run's template must name the URL's database (#7031).

Clone names are ``ai_memory_t_<run id>_<10-digit unix seconds>_<8 hex>``; the
run id is ``[a-z0-9]{1,20}``. The Rust helper (``tests/common/pg_isolate.rs``)
uses the same shape.

Exit codes: 0 success, 2 usage or wrapper error (fails closed), 3 a clone
could not be minted or held, 143 terminated, otherwise the worst exit code of
the cargo runs. ``setup`` and ``teardown`` also exit 5 when a database of this
run is still on the server (or may be, after a CREATE without a clean answer),
naming it, and 128 + the signal number after SIGTERM / SIGINT / SIGHUP; 5 wins
over a signal, a signal over 2. ``EXIT_STATES`` below is the one table of what
each code means (``--help`` prints it). Standard library only, Python 3.12+.
"""
import argparse
import contextlib
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
from typing import Dict, IO, Iterator, List, Optional, Set, Tuple
from urllib.parse import SplitResult, parse_qsl, unquote, urlsplit


def _load_workflow_annotation():
    """The shared module at WA_RELATIVE_PATH from this file's real directory, by path only, never through
    sys.path; every name in WA_REQUIRED must be a callable of it (#9365, one shape in every script)."""
    import importlib.util
    import os
    path = os.path.normpath(os.path.join(os.path.dirname(os.path.realpath(__file__)), WA_RELATIVE_PATH))
    loaded = sys.modules.get("workflow_annotation")
    if loaded is not None and os.path.realpath(getattr(loaded, "__file__", None) or "") == path:
        module = loaded
    else:
        spec = importlib.util.spec_from_file_location("workflow_annotation", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)  # absent, unreadable or broken: it raises here, the try below catches it
    missing = [name for name in WA_REQUIRED if not callable(getattr(module, name, None))]
    if missing:
        raise AttributeError("workflow_annotation.py lacks " + ", ".join(missing))
    if loaded is None:
        sys.modules["workflow_annotation"] = module
    return module


# The one shared-module load shape of scripts/ (#9365, ruling bcd0a15c; LoaderShape pins it).
WA_PROG = "pg_isolated_binary"
WA_RELATIVE_PATH = "../ci/workflow_annotation.py"
WA_REQUIRED = ("annotation", "end_group_line", "env_file_value", "log_line")
WA_EXIT_LOAD_REFUSED = 4  # a failed shared-module load, before any child runs (2 usage, 3 mint, 143 terminated, else the child's)
WA_ERROR_TO_STDERR = True  # setup --emit-env writes stdout to $GITHUB_ENV

try:
    wa = _load_workflow_annotation()
except (Exception, SystemExit) as exc:  # any failed load: one fixed line built without the module, then exit
    wa_cause = type(exc).__name__
    print("%s: refused: shared module workflow_annotation.py next to the script cannot be loaded (%s)"
          % (WA_PROG, wa_cause if wa_cause.isidentifier() else "BaseException"), file=sys.stderr, flush=True)
    print("::error title=pg_isolated_binary refused::pg_isolated_binary: refused: shared module workflow_annotation.py"
          " next to the script cannot be loaded",
          file=sys.stderr if WA_ERROR_TO_STDERR else sys.stdout, flush=True)
    sys.exit(WA_EXIT_LOAD_REFUSED)

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
GUARD_SQL_MAX_BYTES = 65536  # the psql() guard refuses longer SQL unread: its cost is bounded by construction (#7615)
# linear: one quantified class, no alternation, fullmatch on a short env value
_DIGITS_RE = re.compile(r'[0-9]+')
IN_USE_TEXT = 'being accessed by other users'
EXIT_USAGE = 2
EXIT_MINT = 3
EXIT_TERM = 143
EXIT_UNRELEASED = 5  # setup / teardown: a database of this run is (or may be) still on the server
SIGNAL_EXIT_BASE = 128  # setup / teardown exit 128 + signum after a handled signal
HANDLED_SIGNALS = (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)
# C1: the one exit-state table of setup and teardown. The --help epilog and docs/ci/PG-ISOLATION.md show it, the
# tests read it, and _report derives the code from the same facts (a name left, handed, unknown or maybe -> 5;
# else a signal -> 128 + signum; else an error -> 2; else 0).
EXIT_STATES = (
    ('0', 'done: setup leaves only the template it handed to the job; teardown leaves nothing of this run'),
    ('2', 'refused or failed: nothing this invocation created is left; a teardown refused before its first '
          'statement dropped nothing'),
    ('128 + signal', 'interrupted (143 for SIGTERM): nothing this invocation created is left, and a teardown still '
                     'ran every drop'),
    ('5', 'a database of this run is, or may be, still on the server; every such name, or the query that lists '
          'them, is on its own `unreleased:` line'),
)
# decision: an ephemeral base is recognised by a string parse over a new regex, because the parse is linear by
# construction on at most IDENT_MAX characters and every regex of this module is pinned by the regex audit.
EPHEMERAL_PREFIX = 'ai_memory_test_ci_'
EPHEMERAL_RUN_MAX = 20
EPHEMERAL_ATTEMPT_MAX = 5
EPHEMERAL_LEG_MAX = 36  # a 59-byte base (IDENT_MAX minus the template suffix) leaves at most this for the leg
EPHEMERAL_LEG_CHARS = frozenset('abcdefghijklmnopqrstuvwxyz0123456789_')
SHARED_REASON_MAX = 200
WATERMARK_TABLE = 'lineage_integrity_watermark'
LINEAGE_RELATION = 'agent_lineage'
# B2: the relations a watermark row may name, the Python side of the Rust WATERMARKED_RELATIONS
# (src/storage/schema_integrity.rs); a drift test reads the Rust list, so a relation added on one side only is red.
WATERMARKED_RELATIONS = (LINEAGE_RELATION,)
WATERMARK_RELKINDS = ('r', 'p')  # S3: a plain or partitioned table; a view or foreign table can show any mark
WATERMARK_MAX_ROWS = 64  # rows per schema, and schemas per base, the precheck reads (LIMIT one more to see excess)
HIGH_WATER_MAX_DIGITS = 19  # a BIGINT has at most 19 digits
ROW_QUOTE_MAX = 200  # a refused row or count is quoted at most this many characters: the output stays bounded

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
URL_SCHEMES = ('postgres', 'postgresql')
SSLMODES = ('allow', 'disable', 'prefer', 'require', 'verify-ca', 'verify-full')
# P1 #9689: every URL refusal is one of these fixed texts. The builder never receives the URL or any part of it
# (scheme, port, key, value, database name), so no credential can reach a message: redaction by construction.
URL_UNPARSED = 'the URL cannot be parsed'
URL_SCHEME = 'not a postgres URL (the scheme must be postgres or postgresql)'
URL_MULTI_HOST = 'multi-host URLs are not supported'
URL_PORT = 'the URL port is not a number from 0 to 65535'
URL_NO_DB = 'the URL names no database'
URL_DB_UNSAFE = 'the URL database name is not a safe identifier (1 to %d of [A-Za-z0-9_])' % IDENT_MAX
URL_KEY = 'unsupported URL query key (supported: %s)' % ', '.join(sorted(_QUERY_TO_ENV))
URL_SSLMODE = 'the URL sslmode is not one of %s' % ', '.join(SSLMODES)
URL_OPTIONS_BACKSLASH = ("the URL query key 'options' ends in an unescaped backslash; end it with a value character "
                         "or double the backslash")
# linear: one bounded class repetition between anchors
_RUN_ID_RE = re.compile(r'^[a-z0-9]{1,%d}$' % RUN_ID_MAX_LEN)
# linear: bounded class repetitions separated by a fixed underscore, so no two quantifiers can overlap
_ANY_NAME_RE = re.compile(r'^%s_([a-z0-9]{1,%d})_([0-9]{10})_([0-9a-f]{8})$' % (ISOLATED_PREFIX, RUN_ID_MAX_LEN))
# linear: one bounded class repetition between anchors
_IDENT_RE = re.compile(r'^[A-Za-z0-9_]{1,%d}$' % IDENT_MAX)
# linear: fixed prefix, a literal space, then one class repetition to the anchor
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
    """One ``KEY=value`` line for ``$GITHUB_ENV`` (stdout, nothing else; never a second entry)."""
    print(wa.env_file_value(line), flush=True)


def log(msg: str) -> None:
    """Diagnostics go to stderr so ``--emit-env`` stdout stays clean."""
    with _PRINT_LOCK:
        print(wa.log_line('[pg_isolated_binary] ' + msg), file=sys.stderr, flush=True)


# --- names and URLs -------------------------------------------------------

def database_name(url: str) -> str:
    """The database a postgres URL names, after the whole URL is validated (fails closed, fixed texts only)."""
    return _parsed_url(url)[0]


def with_database(url: str, db: str) -> str:
    """Swap the database name, preserving the query string (TLS settings)."""
    base, sep, query = url.partition('?')
    base = base.rstrip('/')
    head = base.rsplit('/', 1)[0]
    return head + '/' + db + (sep + query if sep and query else '')


def quote_ident(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def valid_run_id(run_id: str) -> bool:
    return bool(_RUN_ID_RE.fullmatch(run_id or ''))


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
    found = _ANY_NAME_RE.fullmatch(name or '')
    if not found:
        return None
    if run_id is not None and found.group(1) != run_id:
        return None
    return int(found.group(2))


def run_prefix(run_id: str) -> str:
    return '%s_%s_' % (ISOLATED_PREFIX, checked_run_id(run_id))


def parse_target_line(line: str) -> List[str]:
    """``--test foo`` or ``--bin foo`` only; anything else is refused."""
    found = _TARGET_RE.fullmatch(line.strip())
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
    if not _IDENT_RE.fullmatch(name or ''):
        raise WrapperError('unsafe database name %r' % name)
    return name


def _ascii_digits(text: str, most: int) -> bool:
    """1 to ``most`` ASCII digits and nothing else (``str.isdigit`` alone accepts other scripts' digits)."""
    return 1 <= len(text) <= most and text.isascii() and text.isdigit()


def is_ephemeral_base(name: str) -> bool:
    """``ai_memory_test_ci_<run>_<attempt>_<leg>`` as ci.yml names a job's base: run 1-20 digits, attempt 1-5
    digits, leg 1-36 of ``[a-z0-9_]``. A string parse on an already-checked identifier: linear, no regex."""
    # S4 = C2: a name that is itself a template name (``..._tpl``) or a leg of underscores only is refused.
    if not name.startswith(EPHEMERAL_PREFIX) or name.endswith(TEMPLATE_SUFFIX):
        return False
    parts = name[len(EPHEMERAL_PREFIX):].split('_', 2)
    if len(parts) != 3:
        return False
    run, attempt, leg = parts
    return (_ascii_digits(run, EPHEMERAL_RUN_MAX) and _ascii_digits(attempt, EPHEMERAL_ATTEMPT_MAX)
            and len(leg) <= EPHEMERAL_LEG_MAX and all(ch in EPHEMERAL_LEG_CHARS for ch in leg)
            and any(ch != '_' for ch in leg))  # also refuses an empty leg


def checked_base(db_name: str, allow_shared: Optional[str] = None) -> str:
    """I1: the base a template is built beside. Every name is first a safe identifier; then only an ephemeral CI
    base passes, unless ``allow_shared`` gives a reason for using a shared one. No SQL runs before this, and no
    base is ever created: a refused name stays refused (#7031)."""
    _checked_ident(db_name)
    if allow_shared is not None:
        reason = allow_shared.strip()
        if not reason or len(allow_shared) > SHARED_REASON_MAX or not allow_shared.isprintable():
            raise WrapperError('refusing --allow-shared-base: the reason must be 1 to %d printable characters that '
                               'say why a shared base is safe here' % SHARED_REASON_MAX)
        log('shared base %r allowed: %s' % (db_name, reason))
        return db_name
    if not is_ephemeral_base(db_name):
        raise WrapperError('refusing base database %r: only an ephemeral CI base (%s<run>_<attempt>_<leg>) may back '
                           'a template; pass --allow-shared-base "<reason>" to use a shared base on purpose'
                           % (db_name, EPHEMERAL_PREFIX))
    return db_name


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

def _parsed_url(url: str) -> Tuple[str, Dict[str, str]]:
    """``(database, libpq env)`` of a postgres URL; fails closed. P1 #9689: every refusal is a fixed module text and
    is raised outside any ``except`` block, so neither the message nor a chained exception carries a part of the URL
    (redaction by construction). Checked in order: parse, scheme, one host, port, database, query keys and values.
    Linear in the URL length: one split, one query parse, no regex over the URL."""
    try:
        parts: Optional[SplitResult] = urlsplit(url)
    except ValueError:
        parts = None
    if parts is None:
        raise WrapperError(URL_UNPARSED)
    if parts.scheme not in URL_SCHEMES:
        raise WrapperError(URL_SCHEME)
    if ',' in parts.netloc.rpartition('@')[2]:
        raise WrapperError(URL_MULTI_HOST)
    try:
        port: Optional[int] = parts.port
        port_ok = True
    except ValueError:
        port, port_ok = None, False
    if not port_ok:
        raise WrapperError(URL_PORT)
    db = unquote(parts.path.lstrip('/'))
    if not db:
        raise WrapperError(URL_NO_DB)
    if not _IDENT_RE.fullmatch(db):
        raise WrapperError(URL_DB_UNSAFE)
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
            raise WrapperError(URL_KEY)
        if key == 'sslmode' and value not in SSLMODES:
            raise WrapperError(URL_SSLMODE)
        if key == 'options' and (len(value) - len(value.rstrip('\\'))) % 2:
            raise WrapperError(URL_OPTIONS_BACKSLASH)
        env[var] = value
    return db, env


def libpq_env(url: str) -> Dict[str, str]:
    """Map a postgres URL to libpq environment variables (fails closed, fixed texts only)."""
    return _parsed_url(url)[1]


def _pg_env(url: str) -> Dict[str, str]:
    """The process env with inherited PG* removed and this URL's libpq vars."""
    env = {k: v for k, v in os.environ.items() if not k.startswith('PG')}
    env.update(libpq_env(url))
    return env


def _connect_plan(env: Dict[str, str]) -> Tuple[int, int, int]:
    """``(connect_timeout_secs, addresses, passes)`` libpq may spend connecting: connect_timeout floored at 2 s,
    per resolved address, with a second pass when sslmode may retry without TLS (#7482). Raises on a value that
    is not a plain positive number."""
    connect = env.get('PGCONNECT_TIMEOUT', '').lstrip('0')
    if _DIGITS_RE.fullmatch(connect) is None:
        raise WrapperError('connect_timeout must be a positive whole number of seconds so the server-side '
                           'statement cap can be sized under the psql limit')
    # Anything above the whole psql budget is already unusable. Compare decimal text before int/float
    # arithmetic, after removing padding, so neither Python's integer limit nor float overflow escapes (#7866).
    limit = str(int(PSQL_TIMEOUT_SECS))
    if len(connect) > len(limit) or (len(connect) == len(limit) and connect > limit):
        raise WrapperError('connect_timeout exceeds the psql limit; lower connect_timeout so the server-side '
                           'statement cap can be sized under the psql limit')
    each = max(int(connect), LIBPQ_MIN_CONNECT_SECS)
    host = env.get('PGHOST', '')
    if env.get('PGHOSTADDR') or not host or host.startswith('/'):
        return each, 1, 1
    try:
        port = int(env.get('PGPORT') or 5432)
        addresses = len({info[4] for info in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)}) or 1
    except (OSError, ValueError):
        addresses = 1
    return each, addresses, 2 if env.get('PGSSLMODE', 'prefer') in ('prefer', 'allow') else 1


def _connect_budget_secs(env: Dict[str, str]) -> int:
    """Worst-case seconds libpq may spend connecting (see ``_connect_plan``)."""
    each, addresses, passes = _connect_plan(env)
    return each * addresses * passes


def server_caps_sql(env: Dict[str, str]) -> str:
    """A ``DO`` statement setting session statement_timeout and lock_timeout to the least non-zero of the
    value the server already resolved for this session (startup options, role and database defaults) and the
    wrapper cap; lock_timeout is clamped below the effective statement_timeout (#7453, #7480, #7484, #7519).

    The body pins search_path and names pg_catalog objects, so a caller ``options=-c search_path=...`` naming a
    schema with a shadow ``pg_settings`` or ``set_config`` cannot skip the cap (#7520)."""
    budget = _connect_budget_secs(env)
    cap_ms = int((PSQL_TIMEOUT_SECS - budget - PSQL_CAP_MARGIN_SECS) * 1000)
    gap_ms = int(PSQL_LOCK_GAP_SECS * 1000)
    lock_cap_ms = cap_ms - gap_ms
    if lock_cap_ms <= 0:
        each, addresses, passes = _connect_plan(env)
        asked = int(env.get('PGCONNECT_TIMEOUT', '').lstrip('0'))
        # "floored" only when libpq really raised the value (asked < 2 s); at the floor lowering it changes nothing (#7580)
        used = '%d s, floored from %d s' % (each, asked) if asked < LIBPQ_MIN_CONNECT_SECS else '%d s' % each
        mode = env.get('PGSSLMODE', 'prefer')
        lower = 'lower connect_timeout, ' if each > LIBPQ_MIN_CONNECT_SECS else ''
        fix = (lower + 'reduce the resolved addresses (hostaddr) or set sslmode=require'
               if passes == 2 else
               ('lower connect_timeout or ' if lower else '') + 'reduce the resolved addresses (set hostaddr)')
        raise WrapperError(
            'the connect budget (%d s = connect_timeout %s x %d address(es) x %d sslmode pass(es), '
            'sslmode=%s) leaves no room for a server-side statement cap under the %g s psql limit; %s'
            % (budget, used, addresses, passes, mode, PSQL_TIMEOUT_SECS, fix))
    return (
        "DO $cap$ DECLARE s bigint; l bigint; BEGIN "
        "PERFORM pg_catalog.set_config('search_path', 'pg_catalog, pg_temp', true); "
        "SELECT setting::bigint INTO s FROM pg_catalog.pg_settings WHERE name = 'statement_timeout'; "
        "SELECT setting::bigint INTO l FROM pg_catalog.pg_settings WHERE name = 'lock_timeout'; "
        "IF s = 0 OR s > %(cap)d THEN s := %(cap)d; END IF; "
        "IF l = 0 OR l > %(lock)d THEN l := %(lock)d; END IF; "
        "IF l >= s THEN l := CASE WHEN s > %(twice)d THEN s - %(gap)d ELSE greatest(s / 2, 1) END; END IF; "
        "PERFORM pg_catalog.set_config('statement_timeout', s::text || 'ms', false); "
        "PERFORM pg_catalog.set_config('lock_timeout', l::text || 'ms', false); "
        "END $cap$" % {'cap': cap_ms, 'lock': lock_cap_ms, 'gap': gap_ms, 'twice': 2 * gap_ms})


# Caller SQL that would undo the server cap or run outside it (#7521, #7550, #7551, #7575-#7579). Round 12 of a
# deny-list guard: the deny-list SHAPE was the defect, so the guard now refuses any MENTION. The SQL is tokenised
# the way the PostgreSQL scanner (src/backend/parser/scan.l, parser.c base_yylex) reads it; then the statement is
# refused when ANY identifier or string-literal token, anywhere in it, equals a name from _FORBIDDEN_NAMES (after
# quoted, U&, UESCAPE and E-string decoding and ASCII lower-casing), or when it holds a second statement, DO,
# DISCARD, RESET ALL, ALTER SYSTEM, SET [SESSION] AUTHORIZATION, CREATE [OR REPLACE] FUNCTION, CREATE [OR REPLACE]
# PROCEDURE, CALL (a function or procedure body is code the guard cannot read, #7704), an octal escape above \377 in an
# E-string, or in a plain literal such as '\563' (whether a backslash escapes there depends on
# standard_conforming_strings, which the wrapper does not control; PostgreSQL keeps only the low byte, so the decode
# could differ, #7703, #7717), or anything the guard cannot tokenise.
#
# scan.l rules mirrored here:
#   space              [ \t\n\r\f\v]  ASCII only; every other byte (a no-break space, U+2003, ...) is part of a token
#   newline            [\n\r]
#   comment            "--"{non_newline}*  with non_newline [^\n\r]: a line comment ends at \n OR \r (#7575)
#   ident_start        [A-Za-z\200-\377_]   ident_cont  [A-Za-z\200-\377_0-9\$]
#   dolq_start/cont    [A-Za-z\200-\377_]   [A-Za-z\200-\377_0-9]
#   xq/xus             a doubled quote is a quote; xe also reads backslash escapes; xb/xh (B'' X'') have neither
#   N'..'              the NCHAR keyword, then an ordinary '..' literal (scan.l xnstart: yyless(1))
#   quotecontinue      a literal followed by whitespace holding a newline (and `--` comments) and another quote is
#                      ONE literal read in the SAME mode (E'a'<newline>'\'...' stays an E string)
#   UESCAPE            parser.c base_yylex reads the token AFTER a U& token, so whitespace and comments may sit
#                      between (#7576); the escape must be one simple string literal of one ASCII character
_SPACE = ' \t\n\r\f\v'
# linear: one character class, matched at one index
_IDENT_START_RE = re.compile(r'[A-Za-z_\x80-\U0010ffff]')
# linear: one quantified class and nothing after it, so there is nothing to give back
_IDENT_BODY_RE = re.compile(r'[A-Za-z0-9_$\x80-\U0010ffff]*')
# linear: a start class then one quantified class (disjoint from the closing dollar), tried once per dollar sign
_DOLLAR_TAG_RE = re.compile(r'\$(?:[A-Za-z_\x80-\U0010ffff][A-Za-z0-9_\x80-\U0010ffff]*)?\$')
# linear: one quantified class, fullmatch on at most eight characters
_HEX_RE = re.compile(r'[0-9A-Fa-f]+')
_FORBIDDEN_NAMES = frozenset((
    'statement_timeout', 'lock_timeout', 'idle_in_transaction_session_timeout', 'idle_session_timeout',
    'transaction_timeout', 'session_authorization', 'role', 'set_config', 'pg_settings', 'pg_reload_conf'))
_STR, _STR_ALT, _IDENT, _QIDENT, _SEMI, _OTHER = 'str', 'str-alt', 'ident', 'qident', ';', 'other'
_USTR, _UIDENT = 'ustr', 'uident'          # pass-one only: a U& token whose UESCAPE is not resolved yet
_E_SIMPLE = {'b': '\b', 'f': '\f', 'n': '\n', 'r': '\r', 't': '\t'}


def _ascii_lower(text: str) -> str:
    """Fold A-Z only, as the server does for a UTF-8 identifier (``str.lower`` also folds U+212A and friends)."""
    return ''.join(chr(ord(c) + 32) if 'A' <= c <= 'Z' else c for c in text)


def _unicode_unescape(body: str, escape: str) -> str:
    """Decode the ``\\XXXX`` / ``\\+XXXXXX`` / doubled-escape forms of a ``U&`` literal or identifier."""
    out: List[str] = []
    i = 0
    while i < len(body):
        ch = body[i]
        if ch != escape:
            out.append(ch)
            i += 1
        elif body[i + 1:i + 2] == escape:
            out.append(escape)
            i += 2
        else:
            width = 6 if body[i + 1:i + 2] == '+' else 4
            digits = body[i + 1 + (width == 6):i + 1 + (width == 6) + width]
            if len(digits) != width or _HEX_RE.fullmatch(digits) is None:
                raise WrapperError('refusing SQL with a malformed Unicode escape (%r)' % body[:40])
            try:
                out.append(chr(int(digits, 16)))
            except (ValueError, OverflowError):
                raise WrapperError('refusing SQL with an invalid Unicode code point (%r)' % body[:40])
            i += 1 + (width == 6) + width
    return ''.join(out)


def _decode_e(body: str, literal: str = 'an E-string') -> str:
    """Decode the escapes of an ``E''`` literal body (``\\n``, ``\\101``, ``\\x41``, ``\\u0041``, ``\\U00000041``,
    ``\\'``; any other escaped character is itself) and a doubled quote. A malformed escape is kept verbatim: the
    server rejects it, and the raw text is still compared. An octal escape above ``\\377`` raises ``WrapperError``;
    ``literal`` names the literal kind in that error ('an E-string' or 'a plain-literal', #7717)."""
    out: List[str] = []
    i, n = 0, len(body)
    while i < n:
        ch = body[i]
        if ch == "'" and body[i + 1:i + 2] == "'":
            out.append("'")
            i += 2
        elif ch != '\\' or i + 1 >= n:
            out.append(ch)
            i += 1
        else:
            nxt = body[i + 1]
            if nxt in _E_SIMPLE:
                out.append(_E_SIMPLE[nxt])
                i += 2
            elif nxt in '01234567':
                j = i + 1
                while j < n and j < i + 4 and body[j] in '01234567':
                    j += 1
                value = int(body[i + 1:j], 8)
                if value > 0o377:
                    # PostgreSQL keeps only the low byte of an octal escape (scan.l unsigned char), so a value above
                    # \377 could decode differently here: refuse it (#7703).
                    raise WrapperError('refusing SQL with %s octal escape above \\377 (PostgreSQL keeps only '
                                       'the low byte; the guard cannot read it the same way) (%r)'
                                       % (literal, body[:40]))
                out.append(chr(value))
                i = j
            elif nxt in 'xuU':
                width = {'x': 2, 'u': 4, 'U': 8}[nxt]
                j = i + 2
                while j < n and j < i + 2 + width and body[j] in '0123456789abcdefABCDEF':
                    j += 1
                digits = body[i + 2:j]
                try:
                    out.append(chr(int(digits, 16)) if digits else nxt)
                except (ValueError, OverflowError):
                    out.append(body[i:j])
                i = j
            else:
                out.append(nxt)
                i += 2
    return ''.join(out)


def _line_comment_end(sql: str, i: int) -> int:
    """Index of the first newline or CR at or after ``i`` (``len(sql)`` when the comment runs to the end)."""
    n = len(sql)
    while i < n and sql[i] not in '\n\r':
        i += 1
    return i


def _continuation_quote(sql: str, i: int) -> int:
    """Index of the quote that continues a literal ending just before ``sql[i]``, or ``-1``. scan.l quotecontinue:
    blanks and ``--`` comments, a newline, then whitespace (newlines included) and ``--`` comments, then a quote.
    A plain forward scan, one pass, no backtracking: the regex it replaces backtracked exponentially (#7615)."""
    n = len(sql)
    while i < n and (sql[i] in ' \t\f' or sql.startswith('--', i)):
        i = _line_comment_end(sql, i) if sql[i] == '-' else i + 1
    if i >= n or sql[i] not in '\n\r':
        return -1
    i += 1
    while i < n:
        if sql[i] in _SPACE:
            i += 1
        elif sql.startswith('--', i):
            i = _line_comment_end(sql, i)
            if i >= n:
                return -1
            i += 1                               # the comment's own newline
        else:
            break
    return i if i < n and sql[i] == "'" else -1


def _literal(sql: str, i: int, doubling: bool, backslash: bool) -> Tuple[int, str]:
    """``(end, raw_body)`` of the quoted run whose opening quote is ``sql[i]``, following quote-continuation
    (a newline between two quotes joins them into one literal read the same way). ``doubling`` is whether ``''``
    is an escaped quote, ``backslash`` whether a backslash escapes the next character. Raises on an unterminated
    run (fail closed)."""
    parts: List[str] = []
    while True:
        start = i + 1
        i = start
        while True:
            if i >= len(sql):
                raise WrapperError('refusing SQL the guard cannot tokenise: unterminated quote (%r)' % sql[:60])
            ch = sql[i]
            if backslash and ch == '\\':
                i += 2
            elif ch == "'":
                if doubling and sql[i + 1:i + 2] == "'":
                    i += 2
                else:
                    break
            else:
                i += 1
        parts.append(sql[start:i])
        joined = _continuation_quote(sql, i + 1)
        if joined < 0:
            return i + 1, ''.join(parts)
        i = joined


def _quoted_ident_end(sql: str, i: int) -> int:
    """Index just past the closing double quote of the identifier whose opening quote is ``sql[i]``."""
    i += 1
    while i < len(sql):
        if sql[i] == '"':
            if sql[i + 1:i + 2] == '"':
                i += 2
            else:
                return i + 1
        else:
            i += 1
    raise WrapperError('refusing SQL the guard cannot tokenise: unterminated quote (%r)' % sql[:60])


def _plain_literal(sql: str, i: int, raw: List[Tuple[str, str]]) -> int:
    """Read an ordinary ``'..'`` literal at ``sql[i]``; appends its token(s); returns the index after it.

    Whether a backslash escapes depends on standard_conforming_strings (a session setting the wrapper does not
    control), so the literal is read both ways: if the two readings end at different places the statement is
    refused; if they end together but decode differently both values are kept for the name check (#7577). An octal
    escape above ``\\377`` in a plain literal such as ``'\\563'`` is refused too, as in an E-string (#7717)."""
    end, body = _literal(sql, i, True, False)
    plain = body.replace("''", "'")
    if '\\' not in sql[i:end]:
        raw.append((_STR, plain))
        return end
    end_bs, body_bs = _literal(sql, i, True, True)
    if end_bs != end:
        raise WrapperError('refusing SQL whose string literal ends differently under '
                           'standard_conforming_strings=off (%r)' % sql[:60])
    raw.append((_STR, plain))
    decoded = _decode_e(body_bs, 'a plain-literal')
    if decoded != plain:
        raw.append((_STR_ALT, decoded))
    return end


def _tokenise(sql: str) -> List[Tuple[str, str]]:
    """``(kind, value)`` tokens of one SQL text: unquoted identifiers ASCII-lower-cased, quoted ones decoded, every
    literal and dollar quote one ``str`` token, comments dropped (``/* */`` nests). Raises ``WrapperError`` on
    anything it cannot tokenise, including a plain literal whose end differs depending on
    standard_conforming_strings. B'' and X'' literals have no quote escape and no backslash escape in scan.l
    (xb/xh read ``[^']*``), so they end at the first quote under both settings."""
    raw: List[Tuple[str, str]] = []
    i, n = 0, len(sql)
    while i < n:
        ch = sql[i]
        nxt = sql[i + 1:i + 2]
        if ch in _SPACE:
            i += 1
        elif ch == '-' and nxt == '-':
            while i < n and sql[i] not in '\n\r':
                i += 1
        elif ch == '/' and nxt == '*':
            depth, i = 1, i + 2
            while depth:
                if i >= n:
                    raise WrapperError('refusing SQL the guard cannot tokenise: unterminated comment (%r)' % sql[:60])
                if sql.startswith('/*', i):
                    depth, i = depth + 1, i + 2
                elif sql.startswith('*/', i):
                    depth, i = depth - 1, i + 2
                else:
                    i += 1
        elif ch == ';':
            raw.append((_SEMI, ';'))
            i += 1
        elif ch == '\\':
            raise WrapperError('refusing SQL with a backslash outside a literal (a psql meta-command?) (%r)'
                               % sql[:60])
        elif ch == "'":
            i = _plain_literal(sql, i, raw)
        elif ch == '"':
            end = _quoted_ident_end(sql, i)
            raw.append((_QIDENT, _ascii_lower(sql[i + 1:end - 1].replace('""', '"'))))
            i = end
        elif ch == '$' and _DOLLAR_TAG_RE.match(sql, i):
            tag = _DOLLAR_TAG_RE.match(sql, i).group(0)
            close = sql.find(tag, i + len(tag))
            if close < 0:
                raise WrapperError('refusing SQL the guard cannot tokenise: unterminated dollar quote (%r)'
                                   % sql[:60])
            raw.append((_STR, sql[i + len(tag):close]))
            i = close + len(tag)
        elif _IDENT_START_RE.match(ch):
            end = i + 1 + len(_IDENT_BODY_RE.match(sql, i + 1).group(0))
            lowered = _ascii_lower(sql[i:end])
            quote_next = sql[end:end + 1] == "'"
            if lowered == 'e' and quote_next:
                close, body = _literal(sql, end, True, True)
                raw.append((_STR, _decode_e(body)))
                i = close
            elif lowered in ('b', 'x') and quote_next:
                close, body = _literal(sql, end, False, False)
                raw.append((_STR, body))
                i = close
            elif lowered == 'n' and quote_next:
                i = end                          # NCHAR keyword; the quote is read as an ordinary literal
            elif lowered == 'u' and sql[end:end + 2] == "&'":
                close, body = _literal(sql, end + 1, True, False)
                raw.append((_USTR, body.replace("''", "'")))
                i = close
            elif lowered == 'u' and sql[end:end + 2] == '&"':
                close = _quoted_ident_end(sql, end + 1)
                raw.append((_UIDENT, sql[end + 2:close - 1].replace('""', '"')))
                i = close
            else:
                raw.append((_IDENT, lowered))
                i = end
        else:
            raw.append((_OTHER, ch))
            i += 1
    return _resolve_uescape(raw)


def _resolve_uescape(raw: List[Tuple[str, str]]) -> List[Tuple[str, str]]:
    """Decode every ``U&`` token with its ``UESCAPE '<c>'`` (comments are already gone, so any whitespace or
    comment run between the token and UESCAPE is handled) or the default backslash (#7576)."""
    tokens: List[Tuple[str, str]] = []
    k = 0
    while k < len(raw):
        kind, value = raw[k]
        if kind not in (_USTR, _UIDENT):
            tokens.append((kind, value))
            k += 1
            continue
        escape, used = '\\', 1
        if k + 1 < len(raw) and raw[k + 1] == (_IDENT, 'uescape'):
            ok = k + 2 < len(raw) and raw[k + 2][0] == _STR and len(raw[k + 2][1]) == 1
            ok = ok and not (k + 3 < len(raw) and raw[k + 3][0] == _STR_ALT)
            if not ok:
                raise WrapperError('refusing SQL with a UESCAPE the guard cannot read: it must be followed by one '
                                   'simple one-character string literal (%r)' % value[:40])
            escape, used = raw[k + 2][1], 3
            if ord(escape) > 127 or escape in '+\'"' or escape in _SPACE or _HEX_RE.fullmatch(escape):
                raise WrapperError('refusing SQL with an invalid UESCAPE character (%r)' % value[:40])
        decoded = _unicode_unescape(value, escape)
        tokens.append((_QIDENT, _ascii_lower(decoded)) if kind == _UIDENT else (_STR, decoded))
        k += used
    return tokens


def _refuse_uncapped_sql(sql: str) -> None:
    if len(sql.encode('utf-8', 'surrogatepass')) > GUARD_SQL_MAX_BYTES:
        raise WrapperError('refusing SQL over the %d-byte guard limit (%d characters): the guard stays bounded '
                           'whatever the input (%r)' % (GUARD_SQL_MAX_BYTES, len(sql), sql[:60]))
    tokens = _tokenise(sql)
    if tokens and tokens[-1][0] == _SEMI:
        tokens = tokens[:-1]
    if any(kind == _SEMI for kind, _ in tokens):
        raise WrapperError('refusing SQL with more than one statement: the server cap bounds one statement '
                           'per psql call (%r)' % sql[:80])
    for kind, value in tokens:
        if kind in (_IDENT, _QIDENT, _STR, _STR_ALT) and _ascii_lower(value) in _FORBIDDEN_NAMES:
            raise WrapperError('refusing SQL that mentions %s: the server cap must stay in force; a caller that '
                               'needs it gets its own fixed helper (%r)' % (_ascii_lower(value), sql[:80]))
    words = [value for kind, value in tokens if kind in (_IDENT, _QIDENT)]
    for position, value in enumerate(words):
        ahead = words[position + 1:position + 6]
        while ahead[:1] in (['session'], ['local']):
            ahead = ahead[1:]
        bad = (
            value in ('do', 'discard')
            or (value == 'reset' and ahead[:1] == ['all'])
            or (value == 'alter' and ahead[:1] == ['system'])
            or (value in ('set', 'reset') and ahead[:1] == ['authorization']))
        body = None
        if value == 'create':
            rest = ahead[2:] if ahead[:2] == ['or', 'replace'] else ahead
            if rest[:1] in (['function'], ['procedure']):
                body = 'CREATE ' + rest[0].upper()
        elif value == 'call' and position == 0 and tokens[0][0] == _IDENT:
            body = 'CALL'
        if body is not None:
            raise WrapperError('refusing %s: the guard cannot read a function or procedure body, so the server cap '
                               'could be undone out of its sight; a caller that needs one gets its own fixed helper '
                               '(%r)' % (body, sql[:80]))
        if bad:
            raise WrapperError('refusing SQL that resets the session, alters the system, switches authorization or '
                               'runs code the guard cannot read: the server cap must stay in force (%r)' % sql[:80])


def _run_psql(url: str, sql: str, tuples: bool) -> str:
    """Run ``sql`` under the server-side caps; the caller has already vetted it."""
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


def psql(url: str, sql: str, tuples: bool = False) -> str:
    """Run one statement through psql; returns stdout, raises on failure. Refuses SQL that holds more than one
    statement or mentions anything that could undo the server-side caps (#7521)."""
    _refuse_uncapped_sql(sql)
    return _run_psql(url, sql, tuples)


# The one read the guard would refuse (it names pg_settings and the timeout settings): a fixed statement with no
# caller-supplied text, run under the same server-side caps. It reads, never writes.
_EFFECTIVE_TIMEOUTS_SQL = (
    "SELECT (SELECT setting FROM pg_catalog.pg_settings WHERE name = 'statement_timeout') "
    "|| '/' || (SELECT setting FROM pg_catalog.pg_settings WHERE name = 'lock_timeout')")


def effective_timeouts(url: str) -> Tuple[str, str]:
    """``(statement_timeout, lock_timeout)`` in ms as the server resolved them for a session on ``url``. The only
    argument is the URL; the SQL is a module constant, so this helper cannot be used to run caller SQL."""
    parts = _run_psql(url, _EFFECTIVE_TIMEOUTS_SQL, True).strip().split('/')
    if len(parts) != 2:
        raise WrapperError('could not read the effective timeouts (got %r)' % parts)
    return parts[0], parts[1]


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
    _drop_settled(admin_url, name, attempts)


def _drop_settled(admin_url: str, name: str, attempts: int = DROP_ATTEMPTS) -> None:
    """Plain ``DROP DATABASE IF EXISTS`` (never FORCE) of a name the caller owns, retried while a session drains;
    any other error, or the last in-use answer, is raised."""
    sql = 'DROP DATABASE IF EXISTS %s' % quote_ident(_checked_ident(name))
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


def _describe(exc: BaseException) -> str:
    """The message of a WrapperError, else ``unexpected <type>[: <text>]``: every exception type gets one line."""
    if isinstance(exc, WrapperError):
        return str(exc)
    text = str(exc)
    return 'unexpected %s%s' % (type(exc).__name__, (': %s' % text) if text else '')


class _Interrupted(BaseException):
    """A handled signal arrived; raised only at a checkpoint between two statements, never inside one."""


class _Lifetime:
    """I3/I4, the one ownership guard of setup and teardown. A name is owned only after a CREATE of it succeeded in
    this run; ``release`` drops exactly the owned names (plain DROP, never FORCE) and names every one it could not
    drop in ``left``. ``maybe`` holds a name whose CREATE ended without a clean answer: never dropped, always named.
    ``signum`` is set by the flag-only signal handler; ``checkpoint`` turns it into ``_Interrupted``."""

    def __init__(self) -> None:
        self.owned: List[str] = []
        self.locked: Set[str] = set()
        self.maybe: List[str] = []
        self.left: List[Tuple[str, str]] = []
        self.handed: List[str] = []  # C1: handed to the job, then a signal arrived: still on the server, named
        self.unknown: List[Tuple[str, str, str]] = []  # C1: (run id, cause, listing SQL) of a failed clone listing
        self.signum: Optional[int] = None

    def note_signal(self, signum: int, _frame: object) -> None:
        if self.signum is None:
            self.signum = signum

    def checkpoint(self) -> None:
        if self.signum is not None:
            raise _Interrupted()

    def own(self, name: str) -> None:
        self.owned.append(name)

    def release(self, url: str) -> None:
        """Drop every owned name, newest first. Runs to the end whatever is raised or signalled meanwhile."""
        while self.owned:
            name = self.owned.pop()
            q = quote_ident(name)
            try:
                if name in self.locked:
                    try:
                        psql(url, 'ALTER DATABASE %s WITH IS_TEMPLATE false' % q)
                    except WrapperError:
                        pass  # the DROP below reports what is wrong
                _drop_settled(url, name)
            except BaseException as exc:  # every type: a name not dropped is named, never lost
                self.left.append((name, _describe(exc)))
            self.locked.discard(name)


@contextlib.contextmanager
def _signals(lifetime: _Lifetime) -> Iterator[_Lifetime]:
    """Flag-only handlers for SIGTERM / SIGINT / SIGHUP while setup or teardown runs; the previous handlers are
    restored on the way out. A flag handler never raises inside a statement, so a CREATE is never cut between the
    server's commit and the ownership record (PEP 475 retries the interrupted wait)."""
    previous = {}
    try:
        for sig in HANDLED_SIGNALS:
            previous[sig] = signal.signal(sig, lifetime.note_signal)
        yield lifetime
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def _signal_name(signum: int) -> str:
    try:
        return signal.Signals(signum).name
    except ValueError:
        return 'signal'


def _report(lifetime: _Lifetime, error: Optional[str]) -> int:
    """I4: one line per fact, then the exit code: 5 while a name of this run is (or may be) on the server, else
    128 + signum after a signal, else 2 after an error, else 0."""
    lines = [error] if error else []
    if lifetime.signum is not None:
        lines.append('interrupted by signal %d (%s)' % (lifetime.signum, _signal_name(lifetime.signum)))
    for name, cause in lifetime.left:
        lines.append('unreleased: database %s of this run is still on the server: %s; drop it with a plain DROP '
                     'DATABASE once no session holds it' % (name, cause))
    for name in lifetime.handed:
        signum = lifetime.signum if lifetime.signum is not None else 0
        lines.append("unreleased: database %s of this run is still on the server: setup handed it to the job before "
                     "signal %d (%s) arrived; the job's teardown drops it, or drop it with a plain DROP DATABASE once "
                     "no session holds it" % (name, signum, _signal_name(signum)))
    for run_id, cause, listing in lifetime.unknown:
        lines.append('unreleased: the clones of run %s are unknown, the listing failed: %s; list them with `%s` and '
                     'drop each with a plain DROP DATABASE' % (run_id, cause, listing))
    for name in lifetime.maybe:
        lines.append("unreleased: database %s may exist with no owner record (the CREATE ended without a clean "
                     "answer); check with `SELECT 1 FROM pg_database WHERE datname = '%s'` and drop it with a plain "
                     "DROP DATABASE if this run made it" % (name, name))
    with _PRINT_LOCK:
        for text in lines:
            print(wa.log_line('pg_isolated_binary: %s' % text), file=sys.stderr, flush=True)
    if lifetime.left or lifetime.handed or lifetime.unknown or lifetime.maybe:
        return EXIT_UNRELEASED
    if lifetime.signum is not None:
        return SIGNAL_EXIT_BASE + lifetime.signum
    return EXIT_USAGE if error else 0


def _quoted(text: str) -> str:
    """A bounded excerpt of server output for a refusal message."""
    return text[:ROW_QUOTE_MAX]


def _precheck_read(base_url: str, db_name: str, sql: str) -> str:
    try:
        return psql(base_url, sql, tuples=True)
    except WrapperError as exc:
        raise WrapperError('refusing base database %r: the lineage precheck could not read it: %s' % (db_name, exc))


# S3: every relation of that name is read with its relkind, so a view, materialized view or foreign table that
# shadows the watermark is a refusal, never a silent skip.
_WATERMARK_SCHEMAS_SQL = (
    "SELECT n.nspname, c.relkind FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "
    "WHERE c.relname = '%s' ORDER BY n.nspname LIMIT %d"
    % (WATERMARK_TABLE, WATERMARK_MAX_ROWS + 1))


def _high_water(db_name: str, schema: str, raw: str) -> Dict[str, int]:
    """The highest mark per relation of one schema's watermark rows (B2: every relation of WATERMARKED_RELATIONS).
    Every row must be exactly ``<relation>|<1-19 ASCII digits>``; anything else is a refusal, never a skip (#7157)."""
    rows = [row for row in raw.split('\n') if row]
    if len(rows) > WATERMARK_MAX_ROWS:
        raise WrapperError('refusing base database %r: %s in schema %s has more than %d rows'
                           % (db_name, WATERMARK_TABLE, schema, WATERMARK_MAX_ROWS))
    relations = tuple(WATERMARKED_RELATIONS)
    not_relation = ('relation is not %s' % relations[0] if len(relations) == 1
                    else 'relation is not one of %s' % ', '.join(relations))
    highest: Dict[str, int] = {}
    for row in rows:
        fields = row.split('|')
        why = None
        if len(fields) != 2:
            why = 'not two fields'
        elif fields[0] not in relations:
            why = not_relation
        elif not _ascii_digits(fields[1], HIGH_WATER_MAX_DIGITS):
            why = 'high_water is not a non-negative integer of at most %d digits' % HIGH_WATER_MAX_DIGITS
        if why:
            raise WrapperError('refusing base database %r: %s in schema %s has a row the precheck cannot read '
                               '(%s): %r' % (db_name, WATERMARK_TABLE, schema, why, _quoted(row)))
        mark = int(fields[1])
        highest[fields[0]] = max(highest.get(fields[0], mark), mark)
    return highest


def lineage_precheck(url: str, db_name: str) -> None:
    """I2: refuse a base whose ``lineage_integrity_watermark.high_water`` is above ``count(*)`` of
    ``agent_lineage`` in any schema (#6983). Reads only, on the base itself, one statement per call, every
    answer bounded (schemas and rows LIMIT 65, a row quoted at most ROW_QUOTE_MAX characters)."""
    base_url = with_database(url, db_name)
    rows = [row for row in _precheck_read(base_url, db_name, _WATERMARK_SCHEMAS_SQL).split('\n') if row]
    if len(rows) > WATERMARK_MAX_ROWS:
        raise WrapperError('refusing base database %r: %s sits in more than %d schemas'
                           % (db_name, WATERMARK_TABLE, WATERMARK_MAX_ROWS))
    schemas = []
    for row in sorted(rows):
        schema, _sep, kind = row.rpartition('|')
        if not _IDENT_RE.fullmatch(schema):
            raise WrapperError('refusing base database %r: %s sits in a schema with an unsafe name %r'
                               % (db_name, WATERMARK_TABLE, _quoted(schema or row)))
        if kind not in WATERMARK_RELKINDS:
            raise WrapperError('refusing base database %r: %s in schema %s is not a table (relkind %r); a view or '
                               'foreign table can show any mark, so the precheck reads only a plain or partitioned '
                               'table' % (db_name, WATERMARK_TABLE, schema, _quoted(kind)))
        schemas.append(schema)
    for schema in schemas:
        raw = _precheck_read(base_url, db_name, 'SELECT relation, high_water FROM %s.%s ORDER BY relation LIMIT %d'
                             % (quote_ident(schema), WATERMARK_TABLE, WATERMARK_MAX_ROWS + 1))
        highest = _high_water(db_name, schema, raw)
        for relation in WATERMARKED_RELATIONS:
            if relation not in highest:
                continue
            counted = _precheck_read(base_url, db_name, 'SELECT count(*) FROM %s.%s'
                                     % (quote_ident(schema), quote_ident(relation))).strip()
            if not _ascii_digits(counted, HIGH_WATER_MAX_DIGITS):
                raise WrapperError('refusing base database %r: count(*) of %s.%s is not an integer (%r)'
                                   % (db_name, schema, relation, _quoted(counted)))
            if highest[relation] > int(counted):
                raise WrapperError('refusing base database %r: the append-only relation `%s.%s` REGRESSED from a '
                                   'previously-recorded high-water mark of %d row(s) to %d; a template built beside '
                                   'it would run the suite on a poisoned base (#6983)'
                                   % (db_name, schema, relation, highest[relation], int(counted)))


def setup(url: str, db_name: str, jobs: int = MAX_JOBS, allow_shared: Optional[str] = None,
          lifetime: Optional[_Lifetime] = None) -> str:
    """Classify the base (I1), precheck its lineage (I2), check the live budget, then create the locked template
    under the ownership guard (I3). Returns its name. On any exception the template this call created is dropped
    before the exception goes on; a name that could not be dropped is in ``lifetime.left``."""
    checked_base(db_name, allow_shared)
    url_db = database_name(url)
    if db_name != url_db:
        # S2: CREATE DATABASE runs on the URL database and the precheck reads --db; the two must be one database.
        raise WrapperError('refusing setup --db %r: the URL names database %r; setup connects to the URL database, '
                           'so --db must name the same database' % (db_name, url_db))
    tpl = _checked_ident(template_name(db_name))
    need = required_connections(clamp_jobs(jobs))
    life = _Lifetime() if lifetime is None else lifetime
    try:
        lineage_precheck(url, db_name)
        life.checkpoint()
        most, reserved, now, available = connection_budget(url)
        if available < need:
            raise WrapperError('only %d free connection slots (max_connections=%d, reserved=%d, open now=%d); '
                               '%d needed for %d parallel binaries' % (available, most, reserved, now, need, jobs))
        life.checkpoint()
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
                # Status 1 means refused only when the existence check run just above succeeds with no row. A row,
                # a failed check or any other status (2 lost connection, a negative signal status such as -9, None,
                # an unexpected code) may follow a committed CREATE, so the outcome is unknown: setup neither claims
                # the template nor DROPs it, and the exit names it (#7388, #7400, #7427, #7428, #7200).
                life.maybe.append(tpl)
                raise WrapperError('CREATE DATABASE %s ended without a clean answer; the outcome is unknown and the '
                                   'template may exist with no owner record: %s; %s; to check by hand run `%s` and, '
                                   'if the template is from this run, run `pg_isolated_binary.py teardown --db %s '
                                   '--run-id <run id>`'
                                   % (tpl, exc, why, check, db_name), exc.returncode)
            raise WrapperError('CREATE DATABASE %s was refused; nothing was created or changed: %s' % (tpl, exc))
        life.own(tpl)
        life.checkpoint()
        psql(with_database(url, tpl), 'CREATE EXTENSION IF NOT EXISTS age')
        life.checkpoint()
        psql(with_database(url, tpl), 'CREATE EXTENSION IF NOT EXISTS vector')
        life.checkpoint()
        psql(url, 'ALTER DATABASE %s WITH IS_TEMPLATE true ALLOW_CONNECTIONS false' % q)
        life.locked.add(tpl)
        life.checkpoint()
    except BaseException:
        # Only what this call created is dropped: plain DROP, never FORCE; the primary error stays the one raised.
        done = len(life.left)
        life.release(url)
        for name, cause in life.left[done:]:
            log('WARN could not drop the half-built template %s: %s' % (name, cause))
        raise
    log('template %s ready (%d free connection slots, need %d)' % (tpl, available, need))
    return tpl


def _names(url: str, sql: str) -> List[str]:
    return [n for n in psql(url, sql, tuples=True).split() if _IDENT_RE.fullmatch(n)]


CLONE_LISTING_SQL = "SELECT datname FROM pg_database WHERE starts_with(datname, '%s')"


def teardown(url: str, db_name: str, run_id: str, lifetime: Optional[_Lifetime] = None) -> int:
    """Drop this run's clones, then the template (ALTER IS_TEMPLATE false, then a plain DROP that waits out the
    settle window). Every step is tried whatever the one before raised (C1): a failed listing goes to
    ``lifetime.unknown`` with the query that lists the clones, a name not dropped to ``lifetime.left``, each with
    its cause. Returns how many steps failed."""
    _checked_ident(db_name)
    prefix = run_prefix(run_id)
    tpl = _checked_ident(template_name(db_name))
    life = _Lifetime() if lifetime is None else lifetime
    failed = 0
    listing = CLONE_LISTING_SQL % prefix
    names: List[str] = []
    try:
        names = [n for n in _names(url, listing) if parse_isolated_name(n, run_id) is not None]
    except BaseException as exc:  # every type: unknown clones are named with the listing query, never claimed gone
        failed += 1
        life.unknown.append((run_id, _describe(exc), listing))
        log('WARN could not list the clones of run %s: %s' % (run_id, _describe(exc)))
    for name in names:
        try:
            drop(url, name, run_id)
        except BaseException as exc:  # every type: a name not dropped is named, and the next drop still runs
            failed += 1
            life.left.append((name, _describe(exc)))
            log('WARN could not drop %s: %s' % (name, _describe(exc)))
    q = quote_ident(tpl)
    try:
        try:
            psql(url, 'ALTER DATABASE %s WITH IS_TEMPLATE false' % q)
        except WrapperError as exc:
            log('the template %s was not unlocked (%s); the DROP below reports what is left' % (tpl, exc))
        _drop_settled(url, tpl)
    except BaseException as exc:  # every type: the template not dropped is named
        failed += 1
        life.left.append((tpl, _describe(exc)))
        log('WARN could not drop the template %s: %s' % (tpl, _describe(exc)))
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


def _stderr_note(text: str) -> None:
    """Best-effort stderr line (``text`` without its newline, through ``log_line``, #9365): a closed stderr
    must not stop the signal loop (#7915)."""
    try:
        sys.stderr.write(wa.log_line(text) + "\n")
    except (OSError, ValueError):
        return


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
            except ProcessLookupError:
                continue  # the group already exited: nothing to signal
            except PermissionError as exc:
                # A group the wrapper may not signal can leak: say so (#7892).
                _stderr_note("pg_isolated_binary: cannot signal child group %d with %s: %s"
                             % (pid, signal.Signals(sig).name, exc.strerror or exc))

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
            _out(wa.log_line('[pg_isolated_binary] PASS %s (log %s)' % (label, log_path)))
            for line in results:
                _out(wa.log_line('  ' + line))
            return
        _out(wa.annotation('group', 'FAIL %s (exit %d), last %d lines of %s' % (label, rc, LOG_TAIL_LINES, log_path)))
        for line in _tail(log_path, LOG_TAIL_LINES):
            _out(wa.log_line(line))
        _out(wa.end_group_line())

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
    """Non-blank, non-comment lines of a UTF-8 file; an unreadable file is one refusal line, never a traceback."""
    try:
        with open(path, encoding='utf-8') as handle:
            return [ln.strip() for ln in handle if ln.strip() and not ln.lstrip().startswith('#')]
    except OSError as exc:
        cause = exc.strerror or type(exc).__name__
    except UnicodeError:
        cause = 'not UTF-8 text'
    raise WrapperError('cannot read %r (%s)' % (path, cause))


def _url(args: argparse.Namespace) -> str:
    url = getattr(args, 'url', None) or os.environ.get(URL_VAR)
    if not url:
        raise WrapperError('set %s (or pass --url for local admin use)' % URL_VAR)
    _parsed_url(url)  # P1 #9689: every sub-command refuses a bad URL, with a fixed text, before any SQL
    return url


def _default_log_dir() -> str:
    runner_temp = os.environ.get('RUNNER_TEMP')
    if runner_temp:
        return str(Path(runner_temp) / 'pg-isolate-logs')
    return str(Path(__file__).resolve().parents[2] / '.local-runs' / 'pg-isolate-logs')


def build_parser() -> argparse.ArgumentParser:
    epilog = 'exit codes of setup and teardown:\n' + '\n'.join('  %s: %s' % row for row in EXIT_STATES)
    parser = argparse.ArgumentParser(description=__doc__.split('\n', 1)[0], epilog=epilog,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest='cmd', required=True)
    url_help = 'admin URL for local use (default and CI: $%s; argv is visible to other users)' % URL_VAR

    setup_p = sub.add_parser('setup', help='check the live budget and create the template')
    setup_p.add_argument('--url', help=url_help)
    setup_p.add_argument('--db', help='base database (default: the URL database)')
    setup_p.add_argument('--jobs', type=int, default=MAX_JOBS)
    setup_p.add_argument('--run-id', help='run id for the clone names (default: generated)')
    setup_p.add_argument('--emit-env', action='store_true',
                         help='print %s= and %s= lines for $GITHUB_ENV' % (TEMPLATE_VAR, RUN_ID_VAR))
    setup_p.add_argument('--allow-shared-base', metavar='REASON',
                         help='build the template beside a base that is not an ephemeral CI base, for this reason')

    down = sub.add_parser('teardown', help="drop this run's clones and the template")
    down.add_argument('--url', help=url_help)
    down.add_argument('--db', help='base database (default: the URL database)')
    down.add_argument('--run-id', help='the run whose clones are dropped (default: $%s)' % RUN_ID_VAR)
    down.add_argument('--allow-shared-base', metavar='REASON',
                      help='tear down the template of a base that is not an ephemeral CI base, for this reason')

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
    url_db = database_name(url)
    expected = template_name(url_db)
    if tpl != expected:
        # S2: a clone is minted on the URL database from the template; only that database's template may be used.
        raise WrapperError('refusing run: template %r is not %r, the template of the URL database %r'
                           % (tpl, expected, url_db))
    run_id = checked_run_id(args.run_id or os.environ.get(RUN_ID_VAR))
    targets = [parse_target_line(ln) for ln in read_lines(args.targets_file)]
    residual = set(read_lines(args.residual_file)) if args.residual_file else set()
    available = connection_budget(url)[3]
    width = width_for(available, args.jobs)
    if width < clamp_jobs(args.jobs):
        log(wa.annotation('warning', 'only %d free connection slots: width degraded to %d' % (available, width)))
    env = dict(os.environ)
    env[URL_VAR] = url
    runner = Runner(cargo, args.test_arg, env, tpl, run_id, url, args.log_dir or _default_log_dir(), width)

    def on_signal(signum: int, _frame: object) -> None:
        log('signal %d: stopping dispatch, terminating children, dropping clones' % signum)
        runner.terminate()
    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)
    return runner.run_all(targets, residual)


def _guarded(url: str, body) -> int:
    """Run ``body(lifetime)`` under the flag-only signal handlers; every outcome, including every exception type,
    ends in ``_report`` (I4). Owned names are released before the report."""
    life = _Lifetime()
    error = None
    with _signals(life):
        try:
            body(life)
        except _Interrupted:
            error = None  # the signal itself is the fact: _report prints its line and exits 128 + signum
        except BaseException as exc:  # every type gets a line and a non-zero exit, never a traceback
            error = _describe(exc)
        finally:
            life.release(url)
    return _report(life, error)


def _cmd_setup(args: argparse.Namespace, url: str) -> int:
    db = args.db or database_name(url)

    def body(life: _Lifetime) -> None:
        run_id = checked_run_id(args.run_id or new_run_id())
        tpl = setup(url, db, args.jobs, args.allow_shared_base, life)
        # decision: the hand-over runs with the handled signals blocked over a second checkpoint after the emit,
        # because a signal that lands between the emit and the hand-over would otherwise exit 128+signum with an
        # emitted template nobody names; blocked, a signal before the hand-over drops the template (nothing is
        # emitted), and one after it is delivered once the job owns the template its teardown drops.
        previous = signal.pthread_sigmask(signal.SIG_BLOCK, HANDLED_SIGNALS)
        try:
            life.checkpoint()
            if args.emit_env:
                _emit('%s=%s' % (TEMPLATE_VAR, tpl))
                _emit('%s=%s' % (RUN_ID_VAR, run_id))
            life.owned.clear()  # handed over: from here the template belongs to the job, and teardown drops it
            life.locked.clear()
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous)
        if life.signum is not None:
            # C1: the checkpoint above saw no signal, so this one arrived after the hand-over (delivered at the
            # unmask): the template is the job's and stays on the server; the exit names it, never "nothing left".
            life.handed.append(tpl)
    return _guarded(url, body)


def _cmd_teardown(args: argparse.Namespace, url: str) -> int:
    db = args.db or database_name(url)

    def body(life: _Lifetime) -> None:
        checked_base(db, args.allow_shared_base)
        emitted = os.environ.get(TEMPLATE_VAR)
        if not emitted:
            # S1: a teardown drops a template only when the template this job's setup emitted names it.
            raise WrapperError("refusing teardown --db %r: %s is unset or empty; set it to the template this job's "
                               "setup emitted (%r for this base) before a teardown may drop it"
                               % (db, TEMPLATE_VAR, template_name(db)))
        if emitted != template_name(db):
            raise WrapperError("refusing teardown --db %r: its template %r is not %s=%r, the template this job's "
                               "setup emitted" % (db, template_name(db), TEMPLATE_VAR, emitted))
        teardown(url, db, checked_run_id(args.run_id or os.environ.get(RUN_ID_VAR)), life)
    return _guarded(url, body)


def main(argv: Optional[List[str]] = None) -> int:
    try:
        args = build_parser().parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else EXIT_USAGE
    try:
        url = _url(args)
        if args.cmd == 'setup':
            return _cmd_setup(args, url)
        if args.cmd == 'teardown':
            return _cmd_teardown(args, url)
        if args.cmd == 'sweep':
            sweep(url, args.older_than)
            return 0
        return _cmd_run(args, url)
    except BaseException as exc:  # every type: one line and exit 2, never a traceback (the run path's own codes
        # come back as return values; setup and teardown report inside _guarded)
        print(wa.log_line('pg_isolated_binary: %s' % _describe(exc)), file=sys.stderr)
        return EXIT_USAGE


if __name__ == '__main__':
    sys.exit(main())
