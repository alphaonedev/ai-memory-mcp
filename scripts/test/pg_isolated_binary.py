#!/usr/bin/env python3
"""Per-binary Postgres isolation for the enterprise-fed CI legs (#6383 / #6386).

Behind ``AI_MEMORY_TEST_PG_ISOLATE=1`` (default OFF, set only on the
enterprise-fed legs). Every integration-test binary gets its own database,
cloned from a never-connected template database, so binaries can run side by
side instead of one after another.

Sub-commands (``-h`` on each):

``setup``     create ``<db>_tpl`` (age + vector, ``IS_TEMPLATE true
              ALLOW_CONNECTIONS false``) after asserting ``max_connections``
              covers the parallel width. Fails closed.
``sweep``     drop orphans of killed runs: idle ``ai_memory_t_*`` clones older
              than 600 s and idle ``ai_memory_test_ci_*`` databases older than
              one day. Never touches a database with a live session.
``teardown``  un-mark and drop the template and drop idle leftover clones.
``run``       run ``cargo test --no-fail-fast --test <bin>`` once per binary,
              each against its own minted database, ``--jobs`` at a time, then
              the residual-serial list one at a time on the shared database.

Environment: ``AI_MEMORY_TEST_POSTGRES_URL`` (and optionally
``AI_MEMORY_TEST_AGE_URL``). A clone is named
``ai_memory_t_<10-digit unix seconds>_<8 hex>``, the exact shape the Rust-side
sweep (``tests/common/pg_barrier.rs``) recognises.

Exit codes: 0 success, 2 usage or wrapper error (fails closed), otherwise the
worst exit code of the cargo runs. Standard library only, Python 3.9+.
"""
import argparse
import os
import re
import signal
import subprocess
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional, Set, Tuple

URL_VAR = 'AI_MEMORY_TEST_POSTGRES_URL'
AGE_URL_VAR = 'AI_MEMORY_TEST_AGE_URL'
ISOLATED_PREFIX = 'ai_memory_t'
CI_PREFIX = 'ai_memory_test_ci_'
TEMPLATE_SUFFIX = '_tpl'
MAX_JOBS = 8
PER_BINARY_CONNECTIONS = 18
CONNECTION_HEADROOM = 20
MINT_ATTEMPTS = 3
MINT_RETRY_PAUSE = 0.5
STALE_CLONE_SECS = 600
TEARDOWN_MIN_AGE_SECS = 120
IN_USE_TEXT = 'being accessed by other users'
EXIT_USAGE = 2
EXIT_MINT = 3

_NAME_RE = re.compile(r'^' + ISOLATED_PREFIX + r'_([0-9]{10})_([0-9a-f]{8})$')
_IDENT_RE = re.compile(r'^[A-Za-z0-9_]{1,63}$')
_TARGET_RE = re.compile(r'^--(test|bin) ([A-Za-z0-9_-]+)$')
_PRINT_LOCK = threading.Lock()


class WrapperError(Exception):
    """A condition under which the wrapper refuses to continue (fail closed)."""


def log(msg: str) -> None:
    with _PRINT_LOCK:
        print('[pg_isolated_binary] ' + msg, flush=True)


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


def isolated_db_name(now: Optional[int] = None) -> str:
    stamp = int(time.time()) if now is None else int(now)
    return '%s_%010d_%s' % (ISOLATED_PREFIX, stamp, uuid.uuid4().hex[:8])


def parse_isolated_name(name: str) -> Optional[int]:
    found = _NAME_RE.match(name)
    return int(found.group(1)) if found else None


def parse_target_line(line: str) -> List[str]:
    """``--test foo`` or ``--bin foo`` only; anything else is refused."""
    found = _TARGET_RE.match(line.strip())
    if not found:
        raise WrapperError('refusing target selector %r' % line)
    return ['--' + found.group(1), found.group(2)]


def clamp_jobs(jobs: int) -> int:
    if jobs < 1:
        raise WrapperError('--jobs must be at least 1, got %d' % jobs)
    return min(jobs, MAX_JOBS)


def required_connections(jobs: int) -> int:
    return jobs * PER_BINARY_CONNECTIONS + CONNECTION_HEADROOM


def template_name(db_name: str) -> str:
    return db_name + TEMPLATE_SUFFIX


def _checked_ident(name: str) -> str:
    if not _IDENT_RE.match(name):
        raise WrapperError('unsafe database name %r' % name)
    return name


def psql(url: str, sql: str, tuples: bool = False) -> str:
    """Run one statement through psql; returns stdout, raises on failure."""
    argv = ['psql', url, '-X', '-q', '-v', 'ON_ERROR_STOP=1']
    if tuples:
        argv.append('-At')
    argv += ['-c', sql]
    done = subprocess.run(argv, capture_output=True, text=True)
    if done.returncode != 0:
        raise WrapperError('psql failed (%d): %s' % (done.returncode, (done.stderr or '').strip()))
    return done.stdout or ''


def mint(base_url: str, tpl: str, now: Optional[int] = None) -> Tuple[str, str]:
    """CREATE DATABASE ... TEMPLATE; retry while the template reports in-use."""
    name = isolated_db_name(now)
    sql = 'CREATE DATABASE %s TEMPLATE %s' % (quote_ident(name), quote_ident(tpl))
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


def drop(admin_url: str, name: str) -> None:
    """Drop a minted clone; refuses any name that is not an exact clone name."""
    if parse_isolated_name(name) is None:
        raise WrapperError('refusing to drop %r: not a minted database name' % name)
    psql(admin_url, 'DROP DATABASE IF EXISTS %s WITH (FORCE)' % quote_ident(name))


def run_one(target: List[str], cargo: List[str], test_args: List[str], env: Dict[str, str],
            tpl: str, isolate: bool = True) -> int:
    """One binary: mint, ``cargo test --no-fail-fast --test <bin>``, drop."""
    argv = list(cargo) + list(target)
    if test_args:
        argv += ['--'] + list(test_args)
    child_env = dict(env)
    minted: Optional[str] = None
    admin = env.get(URL_VAR)
    label = target[-1]
    try:
        if isolate:
            if not admin:
                raise WrapperError('%s is not set' % URL_VAR)
            url, minted = mint(admin, tpl)
            child_env[URL_VAR] = url
            if env.get(AGE_URL_VAR):
                child_env[AGE_URL_VAR] = with_database(env[AGE_URL_VAR], minted)
            log('%s -> %s' % (label, minted))
        done = subprocess.run(argv, env=child_env, capture_output=True, text=True)
        with _PRINT_LOCK:
            print('::group::%s (exit %d)' % (label, done.returncode))
            sys.stdout.write(done.stdout or '')
            sys.stdout.write(done.stderr or '')
            print('::endgroup::', flush=True)
        return done.returncode
    except WrapperError as exc:
        log('FAIL %s: %s' % (label, exc))
        return EXIT_MINT
    finally:
        if minted and admin:
            try:
                drop(admin, minted)
            except WrapperError as exc:
                log('WARN could not drop %s (the sweep reclaims it): %s' % (minted, exc))


def _worst(codes: List[int]) -> int:
    norm = [c if c >= 0 else 128 - c for c in codes]
    return max(norm) if norm else 0


def run_all(targets: List[List[str]], residual: Set[str], cargo: List[str], test_args: List[str],
            env: Dict[str, str], tpl: str, jobs: int) -> int:
    """Pool the isolated binaries, then run the residual list serially."""
    if not targets:
        raise WrapperError('no targets to run')
    width = clamp_jobs(jobs)
    pooled = [t for t in targets if t[-1] not in residual]
    serial = [t for t in targets if t[-1] in residual]
    codes: List[int] = []
    if pooled:
        with ThreadPoolExecutor(max_workers=width) as pool:
            futures = [pool.submit(run_one, t, cargo, test_args, env, tpl, True) for t in pooled]
            codes += [f.result() for f in futures]
    for target in serial:
        codes.append(run_one(target, cargo, test_args, env, tpl, isolate=False))
    return _worst(codes)


def setup(url: str, db_name: str, jobs: int = MAX_JOBS) -> str:
    """Create the locked template database. Returns its name."""
    _checked_ident(db_name)
    tpl = _checked_ident(template_name(db_name))
    have = psql(url, 'SHOW max_connections', tuples=True).strip()
    need = required_connections(jobs)
    if not have.isdigit() or int(have) < need:
        raise WrapperError('max_connections=%r is below the %d needed for %d parallel binaries'
                           % (have, need, jobs))
    q = quote_ident(tpl)
    try:
        psql(url, 'ALTER DATABASE %s WITH IS_TEMPLATE false' % q)
    except WrapperError:
        pass  # no leftover template from an earlier attempt
    psql(url, 'DROP DATABASE IF EXISTS %s WITH (FORCE)' % q)
    psql(url, 'CREATE DATABASE %s' % q)
    psql(with_database(url, tpl), 'CREATE EXTENSION IF NOT EXISTS age; CREATE EXTENSION IF NOT EXISTS vector')
    psql(url, 'ALTER DATABASE %s WITH IS_TEMPLATE true ALLOW_CONNECTIONS false' % q)
    log('template %s ready (max_connections=%s, need %d)' % (tpl, have, need))
    return tpl


def _idle(alias: str = 'd') -> str:
    return ('NOT EXISTS (SELECT 1 FROM pg_stat_activity a WHERE a.datname = %s.datname)' % alias)


def _drop_names(url: str, names: List[str], unmark: bool = False) -> int:
    dropped = 0
    for name in names:
        try:
            if unmark:
                try:
                    psql(url, 'ALTER DATABASE %s WITH IS_TEMPLATE false' % quote_ident(name))
                except WrapperError:
                    pass
            psql(url, 'DROP DATABASE IF EXISTS %s WITH (FORCE)' % quote_ident(name))
            dropped += 1
        except WrapperError as exc:
            log('WARN could not sweep %s: %s' % (name, exc))
    return dropped


def sweep(url: str, db_name: str) -> int:
    """Best-effort janitor; a database with a live session is never dropped."""
    _checked_ident(db_name)
    live = quote_ident(db_name)[1:-1]
    clones_sql = (
        "SELECT d.datname FROM pg_database d WHERE d.datname ~ '^%s_[0-9]{10}_[0-9a-f]{8}$' "
        "AND substr(d.datname, %d, 10)::bigint < extract(epoch FROM now())::bigint - %d AND %s"
        % (ISOLATED_PREFIX, len(ISOLATED_PREFIX) + 2, STALE_CLONE_SECS, _idle()))
    old_sql = (
        "SELECT d.datname FROM pg_database d WHERE starts_with(d.datname, '%s') "
        "AND d.datname NOT IN ('%s', '%s') "
        "AND (pg_stat_file('base/' || d.oid || '/PG_VERSION')).modification < now() - interval '1 day' "
        "AND %s" % (CI_PREFIX, live, live + TEMPLATE_SUFFIX, _idle()))
    dropped = 0
    for sql, unmark in ((clones_sql, False), (old_sql, True)):
        try:
            names = [n for n in psql(url, sql, tuples=True).split() if _IDENT_RE.match(n)]
        except WrapperError as exc:
            log('WARN sweep query failed (continuing): %s' % exc)
            continue
        dropped += _drop_names(url, names, unmark)
    log('sweep dropped %d orphan database(s)' % dropped)
    return dropped


def teardown(url: str, db_name: str) -> None:
    """Un-mark and drop the template, then drop idle leftover clones."""
    _checked_ident(db_name)
    tpl = _checked_ident(template_name(db_name))
    leftovers_sql = (
        "SELECT d.datname FROM pg_database d WHERE d.datname ~ '^%s_[0-9]{10}_[0-9a-f]{8}$' "
        "AND substr(d.datname, %d, 10)::bigint < extract(epoch FROM now())::bigint - %d AND %s"
        % (ISOLATED_PREFIX, len(ISOLATED_PREFIX) + 2, TEARDOWN_MIN_AGE_SECS, _idle()))
    try:
        names = [n for n in psql(url, leftovers_sql, tuples=True).split()
                 if parse_isolated_name(n) is not None]
    except WrapperError as exc:
        log('WARN could not list leftover clones: %s' % exc)
        names = []
    q = quote_ident(tpl)
    try:
        psql(url, 'ALTER DATABASE %s WITH IS_TEMPLATE false' % q)
    except WrapperError:
        pass  # already gone
    psql(url, 'DROP DATABASE IF EXISTS %s WITH (FORCE)' % q)
    for name in names:
        try:
            drop(url, name)
        except WrapperError as exc:
            log('WARN could not drop %s: %s' % (name, exc))
    log('teardown dropped %s and %d clone(s)' % (tpl, len(names)))


def read_lines(path: str) -> List[str]:
    with open(path, encoding='utf-8') as handle:
        return [ln.strip() for ln in handle if ln.strip() and not ln.lstrip().startswith('#')]


def _url(args: argparse.Namespace) -> str:
    url = args.url or os.environ.get(URL_VAR)
    if not url:
        raise WrapperError('pass --url or set %s' % URL_VAR)
    return url


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.split('\n', 1)[0])
    sub = parser.add_subparsers(dest='cmd', required=True)
    for name in ('setup', 'sweep', 'teardown'):
        one = sub.add_parser(name)
        one.add_argument('--url', help='admin URL (default: $%s)' % URL_VAR)
        one.add_argument('--db', help='base database (default: the URL database)')
        if name == 'setup':
            one.add_argument('--jobs', type=int, default=MAX_JOBS)
    run = sub.add_parser('run')
    run.add_argument('--jobs', type=int, default=MAX_JOBS)
    run.add_argument('--targets-file', required=True, help='one "--test NAME" / "--bin NAME" per line')
    run.add_argument('--residual-file', help='names that stay serial on the shared database')
    run.add_argument('--template', help='template database (default: <url database>_tpl)')
    run.add_argument('--test-arg', action='append', default=[], help='forwarded after "--" to libtest')
    run.add_argument('cargo', nargs=argparse.REMAINDER, help='-- cargo test --no-fail-fast [features]')
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        url = _url(args)
        db = getattr(args, 'db', None) or database_name(url)
        if args.cmd == 'setup':
            setup(url, db, clamp_jobs(args.jobs))
            return 0
        if args.cmd == 'sweep':
            sweep(url, db)
            return 0
        if args.cmd == 'teardown':
            teardown(url, db)
            return 0
        cargo = args.cargo[1:] if args.cargo[:1] == ['--'] else args.cargo
        if not cargo:
            raise WrapperError('missing the cargo command after "--"')
        targets = [parse_target_line(ln) for ln in read_lines(args.targets_file)]
        residual = set(read_lines(args.residual_file)) if args.residual_file else set()
        tpl = args.template or template_name(db)
        signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
        env = dict(os.environ)
        env[URL_VAR] = url
        return run_all(targets, residual, cargo, args.test_arg, env, tpl, args.jobs)
    except WrapperError as exc:
        print('pg_isolated_binary: %s' % exc, file=sys.stderr)
        return EXIT_USAGE


if __name__ == '__main__':
    sys.exit(main())
