#!/usr/bin/env python3
"""Unit tests for scripts/test/pg_isolated_binary.py (#6383 / #6386, review r2).

Run: python3 -m unittest scripts/ci/tests/test_pg_isolated_binary.py

Offline by default: ``subprocess.run`` / ``subprocess.Popen`` / ``os.killpg``
are replaced by recorders, so the assertions are about exact argument lists,
SQL order, child environments and exit codes. ``LiveEndToEnd`` additionally
runs the real script against the Postgres named by
``AI_MEMORY_TEST_POSTGRES_URL`` and skips when that is unset.
"""
import ast
import contextlib
import io
import importlib.util
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest.mock
import urllib.parse
import uuid
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
SCRIPT = REPO / 'scripts' / 'test' / 'pg_isolated_binary.py'
SPEC = importlib.util.spec_from_file_location('pg_isolated_binary', SCRIPT)
pib = importlib.util.module_from_spec(SPEC)
sys.modules['pg_isolated_binary'] = pib
SPEC.loader.exec_module(pib)

BASE = 'postgres://u:pw@127.0.0.1:5445/ai_memory_test_ci_9_1_x?sslmode=verify-full&sslrootcert=/c/ca.crt'
TPL = 'ai_memory_test_ci_9_1_x_tpl'
RUN = 'r6386'
OTHER = 'zother'
SCRATCH = REPO / '.local-runs' / 'pg-isolate-unittest'


def scratch_dir():
    SCRATCH.mkdir(parents=True, exist_ok=True)
    return tempfile.mkdtemp(dir=str(SCRATCH))


class Result:
    def __init__(self, rc=0, out='', err=''):
        self.returncode = rc
        self.stdout = out
        self.stderr = err


def default_answer(argv, kw):
    """Plausible psql answers: a roomy budget and one live session per clone."""
    sql = argv[-1] if '-c' in argv else ''
    if 'max_connections' in sql:
        return Result(0, '1000|3|0|10\n')
    if 'count(*)' in sql and 'pg_stat_activity' in sql:
        return Result(0, '1\n')
    return Result()


class Recorder:
    """subprocess.run stand-in: records calls, answers from a script."""

    def __init__(self, answer=None):
        self.calls = []
        self.answer = answer or default_answer
        self.lock = threading.Lock()

    def __call__(self, argv, **kw):
        assert isinstance(argv, list), 'argument list, never a shell string'
        assert not kw.get('shell'), 'shell=True is forbidden'
        with self.lock:
            self.calls.append((list(argv), kw))
        return self.answer(list(argv), kw)

    def sql(self):
        return [a[-1] for a, _ in self.calls if '-c' in a]


class FakePopen:
    """subprocess.Popen stand-in for holds (psql) and cargo children."""

    instances = []
    lock = threading.Lock()
    cargo_rc = 0
    cargo_output = 'test result: ok. 1 passed; 0 failed\n'
    block = None  # threading.Event the cargo child waits on, when set

    def __init__(self, argv, **kw):
        assert isinstance(argv, list), 'argument list, never a shell string'
        assert not kw.get('shell'), 'shell=True is forbidden'
        self.argv, self.kw = list(argv), kw
        self.pid = 40000 + len(FakePopen.instances)
        self.returncode = None
        self.stdin = unittest.mock.Mock()
        self.is_hold = argv[0] == 'psql'
        with FakePopen.lock:
            FakePopen.instances.append(self)
        out = kw.get('stdout')
        if not self.is_hold and hasattr(out, 'write'):
            out.write(FakePopen.cargo_output)
            out.flush()

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        if self.is_hold:
            self.returncode = 0
            return 0
        if FakePopen.block is not None:
            FakePopen.block.wait(10)
            if self.returncode is not None:
                return self.returncode
        self.returncode = FakePopen.cargo_rc
        return self.returncode

    def kill(self):
        self.returncode = -9

    @classmethod
    def reset(cls):
        cls.instances = []
        cls.cargo_rc = 0
        cls.cargo_output = 'test result: ok. 1 passed; 0 failed\n'
        cls.block = None

    @classmethod
    def cargo(cls):
        return [p for p in cls.instances if not p.is_hold]


def patched(rec=None):
    """Context: fake run, fake Popen, fake killpg, no sleeping."""
    FakePopen.reset()
    rec = rec or Recorder()
    stack = [unittest.mock.patch.object(pib.subprocess, 'run', rec),
             unittest.mock.patch.object(pib.subprocess, 'Popen', FakePopen),
             unittest.mock.patch.object(pib.os, 'killpg'),
             unittest.mock.patch.object(pib.time, 'sleep')]
    return rec, stack


class Patched:
    def __init__(self, rec=None):
        self.rec, self.stack = patched(rec)

    def __enter__(self):
        self.mocks = [p.__enter__() for p in self.stack]
        return self.rec

    def __exit__(self, *exc):
        for p in reversed(self.stack):
            p.__exit__(*exc)
        return False


def runner(env=None, log_dir=None, width=2):
    env = dict(env or {pib.URL_VAR: BASE, pib.FLAG_VAR: '1', pib.TEMPLATE_VAR: TPL})
    return pib.Runner(cargo=['cargo', 'test', '--no-fail-fast'], test_args=['--test-threads=1'],
                      env=env, tpl=TPL, run_id=RUN, admin=BASE,
                      log_dir=log_dir or scratch_dir(), width=width)


def _pad(prefix, filler, suffix=''):
    return lambda n: prefix + filler * (n - len(prefix) - len(suffix)) + suffix


# Every regex of pg_isolated_binary.py, PINNED (#7615, #7653, #7675): (pattern, flags, one-line linearity reason, a
# TUPLE of hostile-input generators, each taking a size in characters). The test compares this set with the module, so
# a new, changed or removed regex fails until a reviewer edits this table. Each regex is also timed against every one
# of its generators at GUARD_SQL_MAX_BYTES and the slowest counts; no generator claims to be the single worst case.
# The size cap, not any detector, is the real bound. Flags 32 is re.UNICODE, the str default.
PINNED_REGEXES = (
    (r'[0-9]+', re.UNICODE,
     'one quantified class and nothing after it: nothing to give back',
     (_pad('', '0', '!'), _pad('', 'a'), _pad('', '0'))),
    (r'^[a-z0-9]{1,20}$', re.UNICODE,
     'one bounded class repetition between anchors', (_pad('', 'a'), _pad('', 'a', '!'))),
    (r'^ai_memory_t_([a-z0-9]{1,20})_([0-9]{10})_([0-9a-f]{8})$', re.UNICODE,
     'bounded class repetitions separated by fixed underscores: no two quantifiers overlap',
     (_pad('ai_memory_t_', 'a'), _pad('ai_memory_t_', '_'), _pad('', 'a'))),
    (r'^[A-Za-z0-9_]{1,63}$', re.UNICODE,
     'one bounded class repetition between anchors', (_pad('', 'a'), _pad('', 'a', '!'))),
    (r'^--(test|bin) ([A-Za-z0-9_-]+)$', re.UNICODE,
     'fixed prefix, a literal space, then one class repetition to the anchor',
     (_pad('--test ', 'a', '!'), _pad('--test ', 'a'), _pad('--bin ', '-'))),
    (r'[A-Za-z_\x80-\U0010ffff]', re.UNICODE,
     'one character class, matched at one index', (_pad('', '1'), _pad('', 'a'))),
    (r'[A-Za-z0-9_$\x80-\U0010ffff]*', re.UNICODE,
     'one quantified class and nothing after it: nothing to give back',
     (_pad('', 'a', '-'), _pad('', 'a'), _pad('', '$'))),
    (r'\$(?:[A-Za-z_\x80-\U0010ffff][A-Za-z0-9_\x80-\U0010ffff]*)?\$', re.UNICODE,
     'a start class then one quantified class disjoint from the closing dollar, tried once per dollar',
     (_pad('$', 'a'), lambda n: '$1' * (n // 2), _pad('', '$'), _pad('$a', 'a'))),
    (r'[0-9A-Fa-f]+', re.UNICODE,
     'one quantified class and nothing after it: nothing to give back',
     (_pad('', 'f', 'g'), _pad('', 'a'), _pad('', 'f'))),
)

RE_FLAGS = frozenset(('A', 'ASCII', 'DOTALL', 'I', 'IGNORECASE', 'L', 'LOCALE', 'M', 'MULTILINE', 'S', 'U', 'UNICODE',
                      'VERBOSE', 'X'))


def sweep_patterns(namespace):
    """Every re.Pattern held by a module global, directly or one container deep (the runtime sweep, #7674)."""
    found = {}
    for name, value in namespace.items():
        items = value.items() if isinstance(value, dict) else enumerate(value) if isinstance(value, (list, tuple, set, frozenset)) else ()
        if isinstance(value, re.Pattern):
            found[name] = value
        for key, inner in items:
            if isinstance(inner, re.Pattern):
                found['%s[%s]' % (name, key)] = inner
    return found


def _binding_counts(tree):
    """name -> how many places bind it anywhere in the tree (assignment, augmented assignment, for/with/except target,
    walrus, del, def, class, parameter, import, match capture); a name declared global or nonlocal counts twice (#7718)."""
    counts = {}

    def bump(name, times=1):
        counts[name] = counts.get(name, 0) + times

    for node in ast.walk(tree):
        kind = type(node).__name__
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            bump(node.id)
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            for name in node.names:
                bump(name, 2)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bump(node.name)
        elif isinstance(node, ast.arg):
            bump(node.arg)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            bump(node.name)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                bump((alias.asname or alias.name).split('.')[0])
        elif kind in ('MatchAs', 'MatchStar') and node.name:
            bump(node.name)
        elif kind == 'MatchMapping' and node.rest:
            bump(node.rest)
    return counts


def _module_constants(tree):
    """Module-level `NAME = <int or str literal>` assignments whose name is bound exactly once in the whole module and
    never declared global, augmented, deleted or used as another target: the only constants a %-formatted pattern
    may use (#7718). Anything else is not folded, so the collector fails closed."""
    counts = _binding_counts(tree)
    constants = {}
    for node in tree.body:
        if (isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
                and isinstance(node.value, ast.Constant) and isinstance(node.value.value, (int, str))
                and not isinstance(node.value.value, bool) and counts.get(node.targets[0].id) == 1):
            constants[node.targets[0].id] = node.value.value
    return constants


def fold_pattern(node, constants):
    """The concrete pattern of a string literal, or of a %-format of a string literal with module-level int or str
    constants (the shapes of _RUN_ID_RE, _ANY_NAME_RE and _IDENT_RE); None for anything else (fail closed)."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if not (isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod) and isinstance(node.left, ast.Constant)
            and isinstance(node.left.value, str)):
        return None
    operands = node.right.elts if isinstance(node.right, ast.Tuple) else [node.right]
    values = []
    for operand in operands:
        if isinstance(operand, ast.Name) and operand.id in constants:
            values.append(constants[operand.id])
        elif isinstance(operand, ast.Constant) and isinstance(operand.value, (int, str)) \
                and not isinstance(operand.value, bool):
            values.append(operand.value)
        else:
            return None
    try:
        return node.left.value % tuple(values)
    except (TypeError, ValueError):
        return None


# Position of the `flags` parameter in every re.<fn> signature that takes one (#7715).
FLAGS_SLOT = {'compile': 1, 'match': 2, 'search': 2, 'fullmatch': 2, 'findall': 2, 'finditer': 2, 'split': 3,
              'sub': 4, 'subn': 4}
REGEX_INTERNALS = ('sre_compile', 'sre_parse', '_sre')


def _fold_flags(node):
    """The int value of a flags argument built from int literals and re.<FLAG> joined by `|`; None otherwise."""
    if isinstance(node, ast.Constant) and isinstance(node.value, int) and not isinstance(node.value, bool):
        return node.value
    if (isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == 're'
            and node.attr in RE_FLAGS):
        return int(getattr(re, node.attr))
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        left, right = _fold_flags(node.left), _fold_flags(node.right)
        return None if left is None or right is None else left | right
    return None


def _call_flags(fn, call):
    """The constant flags of an `re.<fn>(...)` call read from the positional slot and the keyword: (True, value), or
    (False, None) when the flags are not a constant (a name, a call, `*args`, `**kwargs`, both slots): fail closed."""
    if any(isinstance(arg, ast.Starred) for arg in call.args) or any(kw.arg is None for kw in call.keywords):
        return False, None
    nodes = [kw.value for kw in call.keywords if kw.arg == 'flags']
    slot = FLAGS_SLOT.get(fn)
    if slot is not None and len(call.args) > slot:
        nodes.append(call.args[slot])
    if not nodes:
        return True, 0
    value = _fold_flags(nodes[0]) if len(nodes) == 1 else None
    return value is not None, value


def _import_problems(tree):
    """Imports of re other than a plain top-level `import re`, and any import of sre_compile, sre_parse or _sre (#7714)."""
    problems = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules = [alias.name for alias in node.names
                       if not (alias.name == 're' and alias.asname is None and node in tree.body)]
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules = [node.module]
        else:
            continue
        for module in modules:
            top = module.split('.')[0]
            if top in REGEX_INTERNALS:
                problems.append('line %d: import of %s (regex internals)' % (node.lineno, module))
            elif top == 're':
                problems.append('line %d: import of re other than a plain top-level `import re`' % node.lineno)
    return problems


def _scan_regex_calls(source, pinned_pairs=frozenset()):
    """The static collector: ([(fn, folded pattern)], [(pattern, flags) of each re.compile], problems)."""
    tree = ast.parse(source)
    constants = _module_constants(tree)
    parent = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    pinned_patterns = {pattern for pattern, _flags in pinned_pairs}
    found, compiled, problems = [], [], _import_problems(tree)
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == 're'):
            continue
        if node.attr in RE_FLAGS:
            continue
        call = parent.get(node)
        if not (isinstance(call, ast.Call) and call.func is node):
            problems.append('line %d: re.%s used other than as a call' % (node.lineno, node.attr))
            continue
        pattern = fold_pattern(call.args[0], constants) if call.args else None
        if pattern is None:
            problems.append('line %d: re.%s pattern is not a string literal or a %%-format of module constants'
                            % (node.lineno, node.attr))
            continue
        found.append((node.attr, pattern))
        known, given = _call_flags(node.attr, call)
        if not known:
            problems.append('line %d: re.%s flags is not a constant' % (node.lineno, node.attr))
            continue
        try:
            flags = re.compile(pattern, given).flags
        except (re.error, ValueError, OverflowError, RecursionError):
            problems.append('line %d: re.%s pattern or flags do not compile' % (node.lineno, node.attr))
            continue
        holder = parent.get(call)
        if node.attr == 'compile':
            compiled.append((pattern, flags))
            if not (isinstance(holder, ast.Assign) and holder in tree.body and len(holder.targets) == 1
                    and isinstance(holder.targets[0], ast.Name)):
                problems.append('line %d: re.compile outside a module-level assignment' % node.lineno)
        elif (pattern, flags) not in pinned_pairs:
            if pattern in pinned_patterns:
                problems.append('line %d: re.%s pattern %r not pinned with flags %d' % (node.lineno, node.attr, pattern, flags))
            else:
                problems.append('line %d: re.%s pattern not pinned: %r' % (node.lineno, node.attr, pattern))
    return found, compiled, problems


def static_regex_calls(source, pinned_pairs=frozenset()):
    """The static collector: every `re.<fn>(...)` call of `source` as ([(fn, folded pattern)], problems).

    Fails closed: a call whose pattern is neither a string literal nor a %-format of one with module constants bound
    exactly once is a problem; so is a flags argument that is not a constant (read from the positional slot and the
    keyword of every re.<fn> signature); `re.compile` is only allowed as the value of a module-level `NAME = ...`;
    any other re function needs a (pattern, flags) pair from `pinned_pairs`; a use of `re.<fn>` that is not a call is
    a problem (flag constants are not functions and are judged through the swept pattern's flags); an import of re
    other than a plain top-level `import re`, or of sre_compile, sre_parse or _sre, is a problem.
    """
    found, _compiled, problems = _scan_regex_calls(source, pinned_pairs)
    return found, problems


def regex_audit_problems(source, patterns, pinned):
    """Return the ways a module differs from the pinned regex table (#7653, #7701). A CHANGE DETECTOR, not a sandbox.

    Threat model, in plain words: this detects regex additions and changes made in the ordinary way by a first-party
    author, and times them (the timing test). It is NOT a sandbox against a deliberately evasive author: reaching a
    regex through stdlib reflection (sys.modules, argparse or pathlib internals and the like) is outside the claim,
    and code review covers it. The one import rule is plain: any import of re other than a plain top-level
    `import re` (or of sre_compile, sre_parse, _sre) fails closed, because the collector reads only `re.<fn>`.
    Decision: 3-agent vote (6def5ab6), option C.

    `source` is the module text, `patterns` the swept compiled patterns of its globals (`sweep_patterns`). The audit
    is the union of two views. (a) The static collector (`static_regex_calls`) finds no re.<fn> call with a pattern
    that is not a literal or a %-format of module constants bound once, no non-constant flags, no compile outside a
    module-level assignment, and no other call on an unpinned (pattern, flags) pair. (b) The runtime sweep: every
    swept (pattern, flags) is a pinned row and every pinned row is present, which also catches a regex the static
    collector cannot see. A static compile whose pair has no pinned row and no swept object (del, overwrite) is
    reported too (#7716).
    """
    pins = {(pattern, flags) for pattern, flags, _reason, _generators in pinned}
    _found, compiled, problems = _scan_regex_calls(source, pins)
    swept = {(value.pattern, value.flags) for value in patterns.values()}
    problems.extend('not pinned: %r flags %d' % key for key in sorted(swept - pins))
    problems.extend('pinned but absent: %r flags %d' % key for key in sorted(pins - swept))
    problems.extend('compiled but not pinned (not swept): %r flags %d' % key
                    for key in sorted(set(compiled) - pins - swept))
    return problems


def import_form_clashes(source):
    """Modules imported both as `import X` and as `from X import ...` in `source` (CodeQL py/import-and-import-from,
    alert 524, #7653, #7713). A CodeQL-regression pin, not a sandbox."""
    tree = ast.parse(source)
    plain, named = set(), set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            plain.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            named.add(node.module)
    return sorted(plain & named)


def implicit_concat_lines(source_bytes):
    """Return line numbers where two string literals join implicitly inside a list or set (#7616, #7633).

    Python 3.12 and later tokenise an f-string as FSTRING_START ... FSTRING_END, not STRING; both forms count.
    """
    import io
    import tokenize
    starts = {tokenize.STRING} | ({tokenize.FSTRING_START} if hasattr(tokenize, 'FSTRING_START') else set())
    ends = {tokenize.STRING} | ({tokenize.FSTRING_END} if hasattr(tokenize, 'FSTRING_END') else set())
    fstring_start = getattr(tokenize, 'FSTRING_START', None)
    fstring_end = getattr(tokenize, 'FSTRING_END', None)
    stack, previous, found = [], None, []
    for token in tokenize.tokenize(io.BytesIO(source_bytes).readline):
        if token.type in (tokenize.NL, tokenize.COMMENT, tokenize.ENCODING):
            continue
        if token.type == tokenize.NEWLINE:
            previous = None
            continue
        if token.type in starts and previous is not None and previous.type in ends and stack and stack[-1] in ('[', '{'):
            found.append(token.start[0])
        if token.type == fstring_start:
            stack.append('f')
        elif token.type == fstring_end:
            while stack and stack.pop() != 'f':
                pass
        elif token.type == tokenize.OP and token.string in ('(', '[', '{'):
            stack.append(token.string)
        elif token.type == tokenize.OP and token.string in (')', ']', '}') and stack and stack[-1] != 'f':
            stack.pop()
        previous = token
    return found


class NameAndUrl(unittest.TestCase):
    def test_database_name_ignores_query(self):
        self.assertEqual(pib.database_name(BASE), 'ai_memory_test_ci_9_1_x')

    def test_with_database_preserves_tls_query(self):
        out = pib.with_database(BASE, 'ai_memory_t_r6386_1700000000_0123abcd')
        self.assertEqual(
            out,
            'postgres://u:pw@127.0.0.1:5445/ai_memory_t_r6386_1700000000_0123abcd'
            '?sslmode=verify-full&sslrootcert=/c/ca.crt')

    def test_quote_ident_doubles_quotes(self):
        self.assertEqual(pib.quote_ident('a"b'), '"a""b"')

    def test_safe_target_selector_rejects_shell_metacharacters(self):
        self.assertEqual(pib.parse_target_line('--test foo_bar-1'), ['--test', 'foo_bar-1'])
        self.assertEqual(pib.parse_target_line('--bin ai-memory'), ['--bin', 'ai-memory'])
        for bad in ('--test a;b', '--test $(x)', '--test', '--weird x', '--test a b', ''):
            with self.assertRaises(pib.WrapperError, msg=bad):
                pib.parse_target_line(bad)


class RunIdScoping(unittest.TestCase):
    """Review r1 H2: every clone carries the run id; nothing cross-run."""

    def test_run_id_validation(self):
        self.assertTrue(pib.valid_run_id(RUN))
        self.assertTrue(pib.valid_run_id('a' * pib.RUN_ID_MAX_LEN))
        for bad in ('', 'UP', 'a-b', 'a_b', 'x;y', 'a' * (pib.RUN_ID_MAX_LEN + 1)):
            self.assertFalse(pib.valid_run_id(bad), bad)
        fresh = pib.new_run_id()
        self.assertTrue(pib.valid_run_id(fresh), fresh)
        self.assertNotEqual(fresh, pib.new_run_id())

    def test_minted_name_shape_carries_run_id(self):
        name = pib.isolated_db_name(RUN, 1700000000)
        self.assertRegex(name, r'^ai_memory_t_r6386_[0-9]{10}_[0-9a-f]{8}$')
        self.assertLessEqual(len(pib.isolated_db_name('a' * pib.RUN_ID_MAX_LEN, 1700000000)), 63)
        self.assertEqual(pib.parse_isolated_name(name, RUN), 1700000000)
        self.assertEqual(pib.parse_isolated_name(name), 1700000000, 'any-run parse for the admin sweep')
        self.assertIsNone(pib.parse_isolated_name(name, OTHER), 'another run never matches')
        self.assertIsNone(pib.parse_isolated_name(name, 'r638'), 'prefix of a run id never matches')
        for bad in ('ai_memory_t_1700000000_0123abcd', 'ai_memory_t_r6386_1700000000_0123ABCD',
                    'ai_memory_t_r6386_17_0123abcd', 'ai_memory_test_ci_9_1_x', 'ai_memory_t_',
                    'x_ai_memory_t_r6386_1700000000_0123abcd'):
            self.assertIsNone(pib.parse_isolated_name(bad), bad)
            self.assertIsNone(pib.parse_isolated_name(bad, RUN), bad)

    def test_isolated_db_name_refuses_bad_run_id(self):
        with self.assertRaises(pib.WrapperError):
            pib.isolated_db_name('Bad-Run', 1700000000)


class LibpqEnv(unittest.TestCase):
    """Review r1 L3: the URL and password never reach argv."""

    def test_url_maps_to_libpq_variables(self):
        env = pib.libpq_env(BASE)
        self.assertEqual(env['PGHOST'], '127.0.0.1')
        self.assertEqual(env['PGPORT'], '5445')
        self.assertEqual(env['PGUSER'], 'u')
        self.assertEqual(env['PGPASSWORD'], 'pw')
        self.assertEqual(env['PGDATABASE'], 'ai_memory_test_ci_9_1_x')
        self.assertEqual(env['PGSSLMODE'], 'verify-full')
        self.assertEqual(env['PGSSLROOTCERT'], '/c/ca.crt')
        self.assertIn('PGCONNECT_TIMEOUT', env)

    def test_percent_encoded_credentials_are_decoded(self):
        env = pib.libpq_env('postgresql://a%40b:p%2Fw@h:1/d')
        self.assertEqual((env['PGUSER'], env['PGPASSWORD'], env['PGPORT']), ('a@b', 'p/w', '1'))

    def test_unknown_query_key_or_bad_scheme_fails_closed(self):
        for bad in ('postgres://u:p@h:1/d?weird=1', 'mysql://u:p@h:1/d', 'postgres://u:p@h1,h2:1/d',
                    'postgres://u:p@h:1/'):
            with self.assertRaises(pib.WrapperError, msg=bad):
                pib.libpq_env(bad)

    def test_psql_argv_has_no_url_or_password_and_strips_inherited_pg_vars(self):
        rec = Recorder()
        with unittest.mock.patch.object(pib.subprocess, 'run', rec), \
                unittest.mock.patch.dict(os.environ, {'PGSERVICE': 'evil', 'PGPASSFILE': '/x'}):
            pib.psql(BASE, 'SELECT 1', tuples=True)
        argv, kw = rec.calls[0]
        joined = ' '.join(argv)
        self.assertEqual(argv[0], 'psql')
        self.assertNotIn('postgres://', joined)
        self.assertNotIn('pw', argv)
        self.assertNotIn('127.0.0.1', joined)
        self.assertEqual(kw['env']['PGPASSWORD'], 'pw')
        self.assertNotIn('PGSERVICE', kw['env'])
        self.assertNotIn('PGPASSFILE', kw['env'])
        self.assertIn('ON_ERROR_STOP=1', argv)


class MintAndDrop(unittest.TestCase):
    def test_mint_issues_create_database_template_with_run_id(self):
        rec = Recorder()
        with unittest.mock.patch.object(pib.subprocess, 'run', rec):
            url, name = pib.mint(BASE, TPL, RUN, now=1700000000)
        self.assertEqual(pib.database_name(url), name)
        self.assertEqual(pib.parse_isolated_name(name, RUN), 1700000000)
        self.assertIn('sslmode=verify-full', url)
        self.assertEqual(rec.sql(), ['CREATE DATABASE "%s" TEMPLATE "%s"' % (name, TPL)])

    def test_mint_retries_on_template_in_use_then_succeeds(self):
        state = {'n': 0}

        def answer(argv, kw):
            state['n'] += 1
            if state['n'] < 3:
                return Result(1, '', 'ERROR:  source database "t" is being accessed by other users')
            return Result()
        with unittest.mock.patch.object(pib.subprocess, 'run', Recorder(answer)), unittest.mock.patch.object(pib.time, 'sleep'):
            pib.mint(BASE, TPL, RUN, now=1700000000)
        self.assertEqual(state['n'], 3)

    def test_mint_does_not_retry_other_errors(self):
        rec = Recorder(lambda a, k: Result(1, '', 'ERROR: permission denied to create database'))
        with unittest.mock.patch.object(pib.subprocess, 'run', rec):
            with self.assertRaises(pib.WrapperError):
                pib.mint(BASE, TPL, RUN, now=1700000000)
        self.assertEqual(len(rec.calls), 1)

    def test_drop_never_forces(self):
        rec = Recorder()
        with unittest.mock.patch.object(pib.subprocess, 'run', rec):
            pib.drop(BASE, 'ai_memory_t_r6386_1700000000_0123abcd', RUN)
        self.assertEqual(rec.sql(), ['DROP DATABASE IF EXISTS "ai_memory_t_r6386_1700000000_0123abcd"'])

    def test_drop_refuses_another_runs_clone_and_non_clone_names(self):
        rec = Recorder()
        with unittest.mock.patch.object(pib.subprocess, 'run', rec):
            for name in ('ai_memory_t_zother_1700000000_0123abcd', 'ai_memory_test_ci_9_1_x'):
                with self.assertRaises(pib.WrapperError, msg=name):
                    pib.drop(BASE, name, RUN)
        self.assertEqual(rec.calls, [])

    def test_drop_retries_while_in_use_then_fails_closed(self):
        rec = Recorder(lambda a, k: Result(1, '', 'ERROR: database "x" is being accessed by other users'))
        with unittest.mock.patch.object(pib.subprocess, 'run', rec), unittest.mock.patch.object(pib.time, 'sleep'):
            with self.assertRaises(pib.WrapperError):
                pib.drop(BASE, 'ai_memory_t_r6386_1700000000_0123abcd', RUN)
        self.assertEqual(len(rec.calls), pib.DROP_ATTEMPTS)
        self.assertFalse([s for s in rec.sql() if 'FORCE' in s])

    def test_source_has_no_force_drop(self):
        self.assertFalse('WITH (FORCE)' in SCRIPT.read_text(), 'no FORCE drop in the wrapper')


class Budget(unittest.TestCase):
    """Review r1 M5: the budget is what the server has free right now."""

    def test_budget_subtracts_reserved_and_live_sessions(self):
        rec = Recorder(lambda a, k: Result(0, '200|3|2|150\n'))
        with unittest.mock.patch.object(pib.subprocess, 'run', rec):
            got = pib.connection_budget(BASE)
        self.assertEqual(got, (200, 5, 150, 45))
        self.assertIn('pg_stat_activity', rec.sql()[0])

    def test_width_degrades_to_what_fits_and_fails_closed_at_zero(self):
        per = pib.PER_BINARY_CONNECTIONS + pib.HOLD_CONNECTIONS
        self.assertEqual(pib.width_for(10_000, 8), 8)
        self.assertEqual(pib.width_for(pib.CONNECTION_HEADROOM + 2 * per, 8), 2)
        with self.assertRaises(pib.WrapperError):
            pib.width_for(pib.CONNECTION_HEADROOM + per - 1, 8)

    def test_setup_fails_closed_when_live_budget_is_short(self):
        rec = Recorder(lambda a, k: Result(0, '1000|3|0|950\n') if 'max_connections' in ' '.join(a)
                       else Result())
        with unittest.mock.patch.object(pib.subprocess, 'run', rec):
            with self.assertRaises(pib.WrapperError) as ctx:
                pib.setup(BASE, 'ai_memory_test_ci_9_1_x', 8)
        self.assertIn('connection', str(ctx.exception))
        self.assertFalse([s for s in rec.sql() if s.startswith('CREATE DATABASE')])

    def _setup_with_free_slots(self, free, jobs, **kwargs):
        rec = Recorder()
        err = io.StringIO()
        budget = (100, 3, 100 - 3 - free, free)
        with unittest.mock.patch.object(pib.subprocess, 'run', rec), \
                unittest.mock.patch.object(pib, 'connection_budget', lambda _u: budget), \
                contextlib.redirect_stderr(err):
            got = pib.setup_effective(BASE, 'ai_memory_test_ci_9_1_x', jobs, **kwargs)
        return got, rec, err.getvalue()

    def test_setup_clamps_jobs_to_the_live_budget_and_says_so_6383_r4(self):
        per = pib.PER_BINARY_CONNECTIONS + pib.HOLD_CONNECTIONS
        fit = (87 - pib.CONNECTION_HEADROOM) // per
        (tpl, effective), rec, err = self._setup_with_free_slots(87, 8)
        self.assertEqual((tpl, effective), (TPL, fit))
        self.assertLess(fit, 8)
        notice = ('::notice::[#6383] per-binary isolation clamped jobs 8 -> %d '
                  '(free slots 87, per-binary need %d)' % (fit, per))
        self.assertIn(notice, err.splitlines())
        self.assertIn('CREATE DATABASE "%s"' % TPL, rec.sql())

    def test_setup_without_pressure_keeps_the_requested_jobs_6383_r4(self):
        (_tpl, effective), _rec, err = self._setup_with_free_slots(10_000, 8)
        self.assertEqual(effective, 8)
        self.assertNotIn('clamped', err)

    def test_setup_still_fails_closed_when_not_one_binary_fits_6383_r4(self):
        free = pib.required_connections(1) - 1
        with self.assertRaises(pib.WrapperError) as ctx:
            self._setup_with_free_slots(free, 8)
        self.assertIn('free connection slots', str(ctx.exception))

    def test_no_clamp_keeps_the_fail_closed_behaviour_6383_r4(self):
        with self.assertRaises(pib.WrapperError) as ctx:
            self._setup_with_free_slots(87, 8, clamp=False)
        self.assertIn('172 needed for 8 parallel binaries', str(ctx.exception))
        rec = Recorder()
        with unittest.mock.patch.object(pib.subprocess, 'run', rec), \
                unittest.mock.patch.object(pib, 'connection_budget', lambda _u: (100, 3, 10, 87)), \
                unittest.mock.patch.dict(os.environ, {pib.URL_VAR: BASE}, clear=False), \
                contextlib.redirect_stderr(io.StringIO()):
            rc = pib.main(['setup', '--db', 'ai_memory_test_ci_9_1_x', '--jobs', '8', '--no-clamp'])
        self.assertEqual(rc, pib.EXIT_USAGE)

    def test_emit_env_carries_the_effective_jobs_and_run_reads_it_6383_r4(self):
        rec = Recorder()
        out = []
        with unittest.mock.patch.object(pib.subprocess, 'run', rec), \
                unittest.mock.patch.object(pib, 'connection_budget', lambda _u: (100, 3, 10, 87)), \
                unittest.mock.patch.dict(os.environ, {pib.URL_VAR: BASE}, clear=False), \
                unittest.mock.patch.object(pib, '_emit', out.append), \
                contextlib.redirect_stderr(io.StringIO()):
            rc = pib.main(['setup', '--db', 'ai_memory_test_ci_9_1_x', '--jobs', '8', '--run-id', RUN,
                           '--emit-env'])
        self.assertEqual(rc, 0)
        self.assertIn('%s=3' % pib.JOBS_VAR, out)
        args = pib.build_parser().parse_args(['run', '--targets-file', 'x'])
        with unittest.mock.patch.dict(os.environ, {pib.JOBS_VAR: '3'}, clear=False):
            self.assertEqual(pib.effective_run_jobs(args.jobs), 3)
        with unittest.mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop(pib.JOBS_VAR, None)
            self.assertEqual(pib.effective_run_jobs(args.jobs), pib.MAX_JOBS)
        self.assertEqual(pib.effective_run_jobs(5), 5)

    def test_required_connections_formula(self):
        self.assertEqual(pib.required_connections(8),
                         8 * (pib.PER_BINARY_CONNECTIONS + pib.HOLD_CONNECTIONS) + pib.CONNECTION_HEADROOM)


class TierSteps(unittest.TestCase):
    def test_setup_creates_template_installs_extensions_then_locks_it(self):
        rec = Recorder()
        with unittest.mock.patch.object(pib.subprocess, 'run', rec):
            tpl = pib.setup(BASE, 'ai_memory_test_ci_9_1_x', 8)
        self.assertEqual(tpl, TPL)
        sql = rec.sql()
        self.assertIn('CREATE DATABASE "%s"' % TPL, sql)
        ext = [i for i, s in enumerate(sql) if 'CREATE EXTENSION IF NOT EXISTS age' in s]
        lock = [i for i, s in enumerate(sql) if 'IS_TEMPLATE true ALLOW_CONNECTIONS false' in s]
        self.assertTrue(ext and lock and ext[0] < lock[0], 'extensions before the template is locked')
        ext_env = [k['env'] for a, k in rec.calls if any('CREATE EXTENSION' in x for x in a)][0]
        self.assertEqual(ext_env['PGDATABASE'], TPL, 'extensions install inside the template')
        self.assertFalse([s for s in sql if 'FORCE' in s])

    def test_setup_emit_env_prints_template_and_run_id_lines(self):
        rec = Recorder()
        out = []
        with unittest.mock.patch.object(pib.subprocess, 'run', rec), \
                unittest.mock.patch.dict(os.environ, {pib.URL_VAR: BASE}, clear=False), \
                unittest.mock.patch.object(pib, '_emit', out.append):
            rc = pib.main(['setup', '--db', 'ai_memory_test_ci_9_1_x', '--jobs', '8', '--run-id', RUN,
                           '--emit-env'])
        self.assertEqual(rc, 0)
        self.assertEqual(out[:2], ['%s=%s' % (pib.TEMPLATE_VAR, TPL), '%s=%s' % (pib.RUN_ID_VAR, RUN)])
        self.assertEqual(out[2], '%s=8' % pib.JOBS_VAR)

    def test_teardown_drops_only_this_runs_clones_without_force(self):
        def answer(argv, kw):
            if '-At' in argv:
                return Result(0, 'ai_memory_t_r6386_1700000000_0123abcd\n'
                                 'ai_memory_t_zother_1700000000_0123abcd\n'
                                 'ai_memory_test_ci_9_1_x\n')
            return Result()
        rec = Recorder(answer)
        with unittest.mock.patch.object(pib.subprocess, 'run', rec):
            pib.teardown(BASE, 'ai_memory_test_ci_9_1_x', RUN)
        sql = rec.sql()
        listing = [s for s in sql if s.startswith('SELECT')][0]
        self.assertIn('ai_memory_t_r6386_', listing, 'the listing is scoped to this run')
        drops = [s for s in sql if s.startswith('DROP DATABASE')]
        self.assertIn('DROP DATABASE IF EXISTS "ai_memory_t_r6386_1700000000_0123abcd"', drops)
        self.assertIn('DROP DATABASE IF EXISTS "%s"' % TPL, drops)
        self.assertFalse([s for s in drops if 'zother' in s or s.endswith('"ai_memory_test_ci_9_1_x"')])
        self.assertFalse([s for s in sql if 'FORCE' in s])
        unmark = [i for i, s in enumerate(sql) if 'IS_TEMPLATE false' in s]
        drop_tpl = [i for i, s in enumerate(sql) if s == 'DROP DATABASE IF EXISTS "%s"' % TPL]
        self.assertTrue(unmark and drop_tpl and unmark[0] < drop_tpl[0])

    def test_teardown_requires_a_valid_run_id(self):
        with unittest.mock.patch.object(pib.subprocess, 'run', Recorder()):
            with self.assertRaises(pib.WrapperError):
                pib.teardown(BASE, 'ai_memory_test_ci_9_1_x', 'Bad-Run')

    def test_admin_sweep_needs_an_explicit_age_floor(self):
        with unittest.mock.patch.object(pib.subprocess, 'run', Recorder()):
            with self.assertRaises(pib.WrapperError):
                pib.sweep(BASE, pib.MIN_SWEEP_AGE_SECS - 1)
        self.assertNotEqual(pib.main(['sweep']), 0, '--older-than is required')

    def test_admin_sweep_is_idle_only_aged_and_never_forces(self):
        def answer(argv, kw):
            sql = argv[-1]
            if 'extract(epoch' in sql:
                return Result(0, '1700005000\n')
            if sql.startswith('SELECT'):
                return Result(0, 'ai_memory_t_zother_1700000000_0123abcd\n'
                                 'ai_memory_t_r6386_1700004900_0123abcd\n'
                                 'ai_memory_test_ci_9_1_x\n')
            return Result()
        rec = Recorder(answer)
        with unittest.mock.patch.object(pib.subprocess, 'run', rec):
            dropped = pib.sweep(BASE, 3600)
        self.assertEqual(dropped, ['ai_memory_t_zother_1700000000_0123abcd'])
        listing = [s for s in rec.sql() if 'pg_database' in s][0]
        self.assertIn('pg_stat_activity', listing, 'a database with a live session is never swept')
        self.assertFalse([s for s in rec.sql() if 'FORCE' in s])


class FakePg:
    """A tiny stateful server behind psql: databases, template flag, sessions.

    Understands exactly the statements setup/teardown issue. ``fail`` maps a
    SQL prefix to an error text (rc 1: PostgreSQL 18.6 psql returns 1 for a SQL
    error and reserves 2 for a lost connection). ``lost`` lists SQL prefixes
    that commit on the server but whose psql then reports rc 2.
    Every statement is logged in ``log``.
    """

    def __init__(self, existing=None, fail=None, lost=(), lost_status=2):
        self.lost_status = lost_status
        self.dbs = dict(existing or {})
        self.fail = dict(fail or {})
        self.lost = tuple(lost)
        self.log = []

    def __call__(self, argv, kw):
        sql = argv[-1] if '-c' in argv else ''
        if 'max_connections' in sql:
            return Result(0, '1000|3|0|10\n')
        self.log.append(sql)
        for prefix, text in self.fail.items():
            if sql.startswith(prefix):
                return Result(1, '', text)
        probe = re.match(r"SELECT 1 FROM pg_database WHERE datname = '([^']+)'$", sql)
        if probe:
            return Result(0, '1\n' if probe.group(1) in self.dbs else '')
        found = re.search(r'DATABASE (?:IF EXISTS )?"([^"]+)"', sql)
        name = found.group(1) if found else None
        if sql.startswith('CREATE DATABASE'):
            if name in self.dbs:
                return Result(1, '', 'ERROR:  database "%s" already exists' % name)
            self.dbs[name] = {'template': False, 'sessions': 0}
        elif sql.startswith('ALTER DATABASE'):
            if name not in self.dbs:
                return Result(1, '', 'ERROR:  database "%s" does not exist' % name)
            self.dbs[name]['template'] = 'IS_TEMPLATE true' in sql
        elif sql.startswith('DROP DATABASE'):
            db = self.dbs.get(name)
            if db and db['sessions']:
                return Result(1, '', 'ERROR:  database "%s" is being accessed by other users' % name)
            self.dbs.pop(name, None)
        if sql.startswith(self.lost):
            return Result(self.lost_status, '', 'psql: error: connection to server was lost')
        return Result()

    def touched(self, name):
        return [s for s in self.log if '"%s"' % name in s]


class TemplateOwnership(unittest.TestCase):
    """#7127: setup owns a template only by a successful CREATE."""

    DB = 'ai_memory_test_ci_9_1_x'

    def run_setup(self, pg, db=None):
        with unittest.mock.patch.object(pib.subprocess, 'run', Recorder(pg)):
            return pib.setup(BASE, db or self.DB, 8)

    def assert_foreign_untouched(self, pg, before):
        self.assertEqual(pg.dbs, before)
        self.assertFalse([s for s in pg.log if s.startswith(('ALTER', 'DROP'))],
                         'no ALTER or DROP may run against a database setup did not create')
        self.assertFalse([s for s in pg.log if 'FORCE' in s or 'EXTENSION' in s])

    def test_idle_foreign_template_survives_a_name_collision(self):
        pg = FakePg({TPL: {'template': True, 'sessions': 0}})
        before = {k: dict(v) for k, v in pg.dbs.items()}
        with self.assertRaises(pib.WrapperError) as ctx:
            self.run_setup(pg)
        self.assertIn('already exists', str(ctx.exception))
        self.assert_foreign_untouched(pg, before)

    def test_active_foreign_template_survives_a_name_collision(self):
        pg = FakePg({TPL: {'template': True, 'sessions': 3}})
        before = {k: dict(v) for k, v in pg.dbs.items()}
        with self.assertRaises(pib.WrapperError):
            self.run_setup(pg)
        self.assert_foreign_untouched(pg, before)

    def test_plain_foreign_database_at_the_name_survives(self):
        pg = FakePg({TPL: {'template': False, 'sessions': 0}})
        before = {k: dict(v) for k, v in pg.dbs.items()}
        with self.assertRaises(pib.WrapperError):
            self.run_setup(pg)
        self.assert_foreign_untouched(pg, before)

    def test_permission_refusal_claims_nothing_and_drops_nothing(self):
        pg = FakePg(fail={'CREATE DATABASE': 'ERROR:  permission denied to create database'})
        with self.assertRaises(pib.WrapperError) as ctx:
            self.run_setup(pg)
        self.assertIn('permission denied', str(ctx.exception))
        self.assertEqual(pg.dbs, {})
        self.assertFalse([s for s in pg.log if s.startswith(('ALTER', 'DROP', 'CREATE EXT'))])

    def test_collision_message_names_teardown_and_permission_message_does_not_7371(self):
        pg = FakePg({TPL: {'template': True, 'sessions': 0}})
        with self.assertRaises(pib.WrapperError) as taken:
            self.run_setup(pg)
        self.assertIn('teardown', str(taken.exception))
        self.assertIn('your own earlier run', str(taken.exception))
        self.assertIn('already exists', str(taken.exception))
        denied = FakePg(fail={'CREATE DATABASE': 'ERROR:  permission denied to create database'})
        with self.assertRaises(pib.WrapperError) as refused:
            self.run_setup(denied)
        self.assertNotIn('teardown', str(refused.exception))
        self.assertNotIn('not created by this run', str(refused.exception))
        self.assertIn('nothing was created or changed', str(refused.exception))
        self.assertIn('permission denied', str(refused.exception))

    def test_interrupt_after_create_drops_the_template_and_reraises_7372(self):
        class Interrupted(FakePg):
            def __call__(self, argv, kw):
                sql = argv[-1] if '-c' in argv else ''
                if sql.startswith('CREATE EXTENSION'):
                    self.log.append(sql)
                    raise KeyboardInterrupt
                return FakePg.__call__(self, argv, kw)
        pg = Interrupted()
        with self.assertRaises(KeyboardInterrupt):
            self.run_setup(pg)
        self.assertEqual(pg.dbs, {}, 'the template this run created is dropped on interrupt')
        self.assertEqual([s for s in pg.log if s.startswith('DROP DATABASE IF EXISTS')],
                         ['DROP DATABASE IF EXISTS "%s"' % TPL])
        self.assertFalse([s for s in pg.log if 'FORCE' in s])

    def test_failed_cleanup_drop_does_not_replace_the_original_error_7372(self):
        pg = FakePg(fail={'CREATE EXTENSION': 'ERROR:  extension "age" is not available',
                          'DROP DATABASE': 'ERROR:  cleanup-drop-refused'})
        with unittest.mock.patch.object(pib, 'log') as logged:
            with self.assertRaises(pib.WrapperError) as ctx:
                self.run_setup(pg)
        self.assertIn('extension "age" is not available', str(ctx.exception))
        self.assertNotIn('cleanup-drop-refused', str(ctx.exception))
        warned = [c.args[0] for c in logged.call_args_list if c.args and c.args[0].startswith('WARN')]
        self.assertEqual(len(warned), 1)
        self.assertIn(TPL, warned[0])
        self.assertIn('cleanup-drop-refused', warned[0])

    def test_fake_sql_errors_use_psql_status_one_7376(self):
        pg = FakePg({TPL: {'template': True, 'sessions': 0}}, fail={'ALTER DATABASE': 'ERROR:  boom'})
        taken = pg(['psql', '-c', 'CREATE DATABASE "%s"' % TPL], {})
        self.assertEqual(taken.returncode, 1)
        injected = pg(['psql', '-c', 'ALTER DATABASE "%s" WITH IS_TEMPLATE true' % TPL], {})
        self.assertEqual(injected.returncode, 1)

    def test_lost_connection_after_a_committed_create_refuses_without_alter_or_drop_7376(self):
        pg = FakePg(lost=('CREATE DATABASE',))
        with self.assertRaises(pib.WrapperError) as ctx:
            self.run_setup(pg)
        self.assertFalse([s for s in pg.log if s.startswith(('ALTER', 'DROP', 'CREATE EXT'))])
        text = str(ctx.exception)
        self.assertNotIn('nothing was created', text)
        self.assertIn('may exist', text)
        self.assertIn(TPL, text)
        self.assertIn('teardown', text)
        self.assertIn(self.DB, text)
        self.assertEqual(ctx.exception.returncode, 2)

    def test_signal_killed_or_unexpected_psql_status_is_an_unknown_outcome_7400(self):
        for status in (-9, -15, 4):
            with self.subTest(status=status):
                pg = FakePg(lost=('CREATE DATABASE',), lost_status=status)
                with self.assertRaises(pib.WrapperError) as ctx:
                    self.run_setup(pg)
                text = str(ctx.exception)
                self.assertFalse([s for s in pg.log if s.startswith(('ALTER', 'DROP', 'CREATE EXT'))])
                self.assertNotIn('nothing was created', text)
                self.assertIn('outcome is unknown', text)
                self.assertIn('may exist', text)
                self.assertIn(TPL, text)
                self.assertIn("SELECT 1 FROM pg_database WHERE datname = '%s'" % TPL, text)
                self.assertIn('teardown', text)
                self.assertEqual(ctx.exception.returncode, status)

    def test_status_one_is_proved_by_a_pg_database_check_7405(self):
        refused = {'CREATE DATABASE': 'ERROR:  permission denied to create database'}
        # status 1 and the check finds no row: refused, nothing created
        pg = FakePg(fail=refused)
        with self.assertRaises(pib.WrapperError) as empty:
            self.run_setup(pg)
        self.assertIn('nothing was created or changed', str(empty.exception))
        self.assertIn("SELECT 1 FROM pg_database WHERE datname = '%s'" % TPL, pg.log)
        # status 1 but the check finds a row: unknown
        pg = FakePg({TPL: {'template': False, 'sessions': 0}}, fail=refused)
        with self.assertRaises(pib.WrapperError) as row:
            self.run_setup(pg)
        self.assertNotIn('nothing was created', str(row.exception))
        self.assertIn('outcome is unknown', str(row.exception))
        self.assertIn('the existence check found a database with this name', str(row.exception))
        self.assertNotIn('check itself failed', str(row.exception))
        # status 1 and the check itself fails: unknown
        pg = FakePg(fail=dict(refused, **{'SELECT 1 FROM pg_database': 'ERROR:  check-failed'}))
        with self.assertRaises(pib.WrapperError) as failed:
            self.run_setup(pg)
        self.assertNotIn('nothing was created', str(failed.exception))
        self.assertIn('outcome is unknown', str(failed.exception))
        self.assertIn('the existence check itself failed', str(failed.exception))
        self.assertIn('check-failed', str(failed.exception))
        self.assertNotIn('found a database', str(failed.exception))
        self.assertEqual(failed.exception.returncode, 1)
        self.assertFalse([s for s in pg.log if s.startswith(('ALTER', 'DROP', 'CREATE EXT'))])

    def test_psql_wall_time_is_bounded_7429(self):
        with tempfile.TemporaryDirectory(dir=str(Path(__file__).resolve().parent)) as d:
            stub = Path(d) / 'psql'
            stub.write_text('#!/usr/bin/env python3\nimport time\ntime.sleep(60)\n')
            stub.chmod(0o755)
            env = dict(os.environ, PATH=d + os.pathsep + os.environ.get('PATH', ''))
            with unittest.mock.patch.dict(os.environ, env, clear=True), \
                    unittest.mock.patch.object(pib, 'PSQL_TIMEOUT_SECS', 2.0), \
                    unittest.mock.patch.object(pib, 'CONNECT_TIMEOUT_SECS', '1'), \
                    unittest.mock.patch.object(pib, 'LIBPQ_MIN_CONNECT_SECS', 1), \
                    unittest.mock.patch.object(pib, 'PSQL_CAP_MARGIN_SECS', 0.5), \
                    unittest.mock.patch.object(pib, 'PSQL_LOCK_GAP_SECS', 0.25):
                started = time.monotonic()
                with self.assertRaises(pib.WrapperError) as ctx:
                    pib.psql(BASE, 'SELECT 1')
                self.assertLess(time.monotonic() - started, 20)
                self.assertIn('timed out', str(ctx.exception))
                self.assertIsNone(ctx.exception.returncode)
                # the existence check timing out is "unknown", never "proved absent"
                absent, why = pib._proved_absent(BASE, 'SELECT 1')
                self.assertFalse(absent)
                self.assertIn('the existence check itself failed: psql timed out', why)

    @staticmethod
    def _caps(url=BASE):
        """(statement_ms, lock_ms) the cap statement would set when the server has no stricter value."""
        sql = pib.server_caps_sql(pib._pg_env(url))
        return (int(re.search(r's := (\d+); END IF', sql).group(1)),
                int(re.search(r'l := (\d+); END IF', sql).group(1)))

    def test_psql_sends_the_cap_statement_first_and_the_sql_alone_7447_7481(self):
        rec = Recorder(lambda argv, kw: Result(0, '', ''))
        url = BASE + '&options=-c%20search_path%3Dpublic'
        with unittest.mock.patch.object(pib.subprocess, 'run', rec):
            pib.psql(url, 'SELECT 1')
        argv, kw = rec.calls[0]
        self.assertEqual(argv[-1], 'SELECT 1')
        self.assertEqual(argv.count('-c'), 2)
        first = argv[argv.index('-c') + 1]
        self.assertIn("set_config('statement_timeout'", first)
        self.assertIn("set_config('lock_timeout'", first)
        # the caller's options are passed through untouched; the cap is not an option
        self.assertEqual(kw['env']['PGOPTIONS'], '-c search_path=public')

    def test_every_setup_psql_call_carries_one_statement_7481(self):
        pg = FakePg()
        rec = Recorder(pg)
        with unittest.mock.patch.object(pib.subprocess, 'run', rec):
            pib.setup(BASE, self.DB, 8)
        extensions = [a[-1] for a, _ in rec.calls if a[-1].startswith('CREATE EXTENSION')]
        self.assertEqual(len(extensions), 2)
        for argv, _ in rec.calls:
            self.assertNotIn(';', argv[-1].rstrip(';'), argv[-1])

    def test_server_caps_fire_before_the_client_kill_and_lock_before_statement_7453_7480(self):
        for connect in ('30', '5'):
            with self.subTest(connect=connect), unittest.mock.patch.object(pib, 'CONNECT_TIMEOUT_SECS', connect):
                statement, lock = self._caps()
                budget = pib._connect_budget_secs(pib._pg_env(BASE))
                self.assertLess(lock, statement)
                self.assertLessEqual(statement + budget * 1000 + int(pib.PSQL_CAP_MARGIN_SECS * 1000),
                                     int(pib.PSQL_TIMEOUT_SECS * 1000))
        slow = self._caps(BASE + '&connect_timeout=100')
        self.assertEqual(slow[0] + 100000 + 10000, 300000)
        sql = pib.server_caps_sql(pib._pg_env(BASE))
        self.assertIn('IF l >= s THEN l := CASE WHEN s > 10000 THEN s - 5000 ELSE greatest(s / 2, 1) END; END IF',
                      sql)
        self.assertIn('IF s = 0 OR s > ', sql)
        self.assertIn('IF l = 0 OR l > ', sql)

    def test_connect_timeout_values_that_are_not_plain_digits_are_refused_7453_7483(self):
        for bad in ('300', '0', 'x', '%C2%B2', '%D9%A3', '-1', '1.5', ''):
            with self.subTest(bad=bad), self.assertRaises(pib.WrapperError):
                pib.server_caps_sql(pib._pg_env(BASE + '&connect_timeout=' + bad))

    def test_connect_budget_counts_addresses_floor_and_ssl_retry_7482(self):
        two = [(0, 0, 0, '', ('192.0.2.1', 5432)), (0, 0, 0, '', ('192.0.2.2', 5432))]
        named = 'postgres://db.example:5432/d?%s'
        with unittest.mock.patch.object(pib.socket, 'getaddrinfo', return_value=two):
            env = pib._pg_env(named % 'sslmode=verify-full&connect_timeout=30')
            self.assertEqual(pib._connect_budget_secs(env), 60)
            env = pib._pg_env(named % 'connect_timeout=30')       # sslmode defaults to prefer: a second pass
            self.assertEqual(pib._connect_budget_secs(env), 120)
            env = pib._pg_env(named % 'sslmode=verify-full&connect_timeout=1')   # libpq floors at 2 s
            self.assertEqual(pib._connect_budget_secs(env), 4)
            with self.assertRaises(pib.WrapperError):
                pib.server_caps_sql(pib._pg_env(named % 'sslmode=verify-full&connect_timeout=150'))
        with unittest.mock.patch.object(pib.socket, 'getaddrinfo', side_effect=OSError('no dns')):
            self.assertEqual(pib._connect_budget_secs(pib._pg_env(named % 'sslmode=require&connect_timeout=30')), 30)
        sock = {'PGCONNECT_TIMEOUT': '1', 'PGHOST': '/var/run/postgresql'}
        self.assertEqual(pib._connect_budget_secs(sock), 2)

    def test_lock_clamp_keeps_a_useful_lock_wait_under_a_small_statement_timeout_7519(self):
        sql = pib.server_caps_sql(pib._pg_env(BASE))
        # above twice the gap the lock sits the gap below; at or under it the lock is half, never 1 ms
        self.assertIn('CASE WHEN s > 10000 THEN s - 5000 ELSE greatest(s / 2, 1) END', sql)
        self.assertNotIn('greatest(s - 5000, 1)', sql)

    def test_cap_statement_does_not_resolve_names_through_the_search_path_7520(self):
        sql = pib.server_caps_sql(pib._pg_env(BASE))
        body = sql.split('BEGIN', 1)[1]
        self.assertTrue(body.lstrip().startswith("PERFORM pg_catalog.set_config('search_path', "
                                                 "'pg_catalog, pg_temp', true);"), body[:120])
        self.assertEqual(re.findall(r"(?<![\w.])set_config\(", sql), [])
        self.assertEqual(re.findall(r"(?<![\w.])pg_settings\b", sql), [])
        self.assertEqual(sql.count('pg_catalog.pg_settings'), 2)
        self.assertEqual(sql.count("pg_catalog.set_config('statement_timeout'"), 1)
        self.assertEqual(sql.count("pg_catalog.set_config('lock_timeout'"), 1)

    def test_psql_refuses_more_than_one_statement_and_any_timeout_override_7521(self):
        refused = ['SELECT 1; SELECT 2', 'SELECT pg_sleep(3); SELECT pg_sleep(3)', 'SELECT 1;;',
                   'SET statement_timeout = 0', 'set  LOCAL lock_timeout TO 0', 'RESET statement_timeout',
                   'RESET ALL', 'DISCARD ALL', "SELECT set_config('statement_timeout', '0', false)",
                   "SELECT pg_catalog.set_config('lock_timeout', '0', false)",
                   'ALTER ROLE x SET statement_timeout = 0', 'SET\tstatement_timeout=0']
        for sql in refused:
            rec = Recorder(lambda argv, kw: Result(0, '', ''))
            with self.subTest(sql=sql), unittest.mock.patch.object(pib.subprocess, 'run', rec):
                with self.assertRaises(pib.WrapperError) as ctx:
                    pib.psql(BASE, sql)
                self.assertEqual(rec.calls, [], 'psql was not started')
                self.assertIn('refus', str(ctx.exception))
        allowed = ['SELECT 1', 'SELECT 1;', 'SELECT 1 ;  ', 'SET search_path = public', 'CREATE DATABASE x']
        for sql in allowed:
            rec = Recorder(lambda argv, kw: Result(0, 'ok', ''))
            with self.subTest(sql=sql), unittest.mock.patch.object(pib.subprocess, 'run', rec):
                pib.psql(BASE, sql, tuples=True)
                self.assertEqual(rec.calls[0][0][-1], sql)

    def test_psql_guard_lexer_table_7550_7551(self):
        """The guard tokenises the SQL: quoting forms hide text, comments vanish, escapes decode."""
        refused = [
            # comments between the words, in every spelling
            'RESET/**/ALL', 'RESET /* x */ ALL', 'DISCARD/**/ALL', 'DISCARD -- c\nALL', 'RESET /* a /* nested */ b */ ALL',
            'SET/**/statement_timeout = 0', 'SET statement_timeout/**/TO 0', 'SET lock_timeout = 0',
            'SET LOCAL statement_timeout = 0', 'SET SESSION lock_timeout = 0',
            # quoted and Unicode-escaped names
            'SET "statement_timeout" = 0', 'SET "Statement_Timeout" = 0', 'SET "lock_timeout" TO 0',
            'SET U&"statement\\005ftimeout" = 0', 'SET U&"lock!005ftimeout" UESCAPE \'!\' TO 0',
            'SET U&"statement\\+00005ftimeout" = 0', 'RESET U&"lock\\005ftimeout"',
            'SELECT U&"set\\005fconfig"(\'statement_timeout\', \'0\', false)',
            'SELECT "set_config"(\'a\', \'0\', false)', 'SELECT pg_catalog."SET_CONFIG"(\'a\', \'0\', false)',
            'SELECT pg_catalog . set_config(\'a\', \'0\', false)', 'SELECT SET_CONFIG(\'a\', \'0\', false)',
            "SELECT set_config('a' || 'b', '0', false)",
            'ALTER ROLE x SET statement_timeout = 0', 'ALTER DATABASE d SET lock_timeout TO 0',
            # session-level escapes
            'RESET ALL', 'reset\n\tall', 'DISCARD ALL', 'discard   all',
            'SET SESSION AUTHORIZATION postgres', 'SET LOCAL SESSION AUTHORIZATION x', 'SET/**/SESSION/**/AUTHORIZATION x',
            'RESET SESSION AUTHORIZATION', 'SET ROLE postgres', 'SET LOCAL ROLE x', 'SET SESSION ROLE x', 'RESET ROLE',
            'SET "role" TO x',
            # more than one statement, whatever hides the second
            'SELECT 1; SELECT 2', 'SELECT 1;;', 'SELECT 1; -- c\nSELECT 2', 'SELECT 1 /* a */; /* b */ SELECT 2',
            "SELECT 'a'; SELECT 2", 'SELECT $q$a$q$; SELECT 2', 'SELECT 1 AS "x"; SELECT 2',
            ";SELECT 1", "SELECT 'a;b'; SELECT 2",
            # the dynamic-code carrier cannot be inspected
            'DO $d$ BEGIN PERFORM 1; END $d$', "do language plpgsql 'begin null; end'",
            # a payload after a quote the lexer must close exactly where the server does
            "SELECT E'a\\'; SELECT 2'; SELECT 3", "SELECT E'\\\\'; SET statement_timeout = 0",
            "SELECT 'a'; SET statement_timeout = 0", "SELECT $a$x$a$; SET lock_timeout=0",
            # psql meta commands, and anything the lexer cannot tokenise (fail closed)
            '\\set x 1', "SELECT 'unterminated", 'SELECT "unterminated', 'SELECT 1 /* unterminated',
            'SELECT 1 /* a /* b */', 'SELECT $q$ unterminated', "SELECT E'unterminated\\'", 'SELECT U&"bad\\zz"',
            'SELECT U&"bad\\00"', 'SELECT U&"x" UESCAPE \'\'', "SELECT U&'bad\\zz'",
            # a backslash in a plain literal: refused when the server could read it differently (stdstrings off)
            "SELECT 'a\\'; SELECT 2'; SELECT 3", "SELECT 'a\\' || 'b'",
        ]
        allowed = [
            'SELECT 1', 'SELECT 1;', 'SELECT 1 ;  ', '  SELECT 1 ; -- trailing\n', 'SELECT 1; /* trailing */',
            'SET search_path = public', 'CREATE DATABASE x',
            # a ; hidden in each quoting form
            "SELECT 'a;b'", "SELECT E'a;b'", "SELECT e'a\\';b'", "SELECT 'it''s;'", 'SELECT 1 AS "x;y"', 'SELECT 1 AS "x"";y"',
            'SELECT $q$a;b$q$', 'SELECT $$a;b$$', 'SELECT $t1$a;$t2$ b;$t1$', "SELECT U&'a;b'", "SELECT U&'\\0041;'",
            'SELECT 1 AS U&"x\\003by"', 'SELECT 1 AS U&"x!003by" UESCAPE \'!\'',
            'SELECT 1 -- a;b\n', 'SELECT 1 /* a;b */', 'SELECT 1 /* a /* ; */ ; */', 'SELECT 1; -- ;\n',
            # text that only looks like an override
            "SELECT 'RESET ALL'", "SELECT 'DISCARD ALL'", "SELECT 'SET ROLE x'",
            "SELECT $q$SET statement_timeout = 0$q$", 'SELECT 1 AS "reset all"', 'SELECT 1 /* RESET ALL */',
            'SELECT 1 -- SET statement_timeout\n', "SELECT E'SET statement_timeout'",
            'SELECT 1 AS reset_all', 'SELECT 1 AS discard_all', 'SELECT 1 AS my_set_config',
            'SELECT $1, $2', 'SELECT 1 AS a$b$c',
        ]
        for sql in refused:
            rec = Recorder(lambda argv, kw: Result(0, '', ''))
            with self.subTest(refused=sql), unittest.mock.patch.object(pib.subprocess, 'run', rec):
                with self.assertRaises(pib.WrapperError) as ctx:
                    pib.psql(BASE, sql)
                self.assertEqual(rec.calls, [], 'psql was not started')
                self.assertIn('refus', str(ctx.exception))
        for sql in allowed:
            rec = Recorder(lambda argv, kw: Result(0, 'ok', ''))
            with self.subTest(allowed=sql), unittest.mock.patch.object(pib.subprocess, 'run', rec):
                pib.psql(BASE, sql, tuples=True)
                self.assertEqual(rec.calls[0][0][-1], sql)

    # ---- round 12: refuse any MENTION, not a list of spellings (#7575-#7579) --------------------------------
    MENTION_REFUSED = [
        # #7575: a line comment ends at \r as well as \n, so the statement after it is visible
        "SELECT 1 -- c\r; SET statement_timeout = 0; SELECT current_setting('statement_timeout')",
        'SELECT 1 --c\r;SELECT 2', 'SELECT 1 -- c\r\n; SELECT 2', 'SELECT 1 -- c\r SET statement_timeout = 0',
        # non-ASCII spaces are identifier bytes to the server: the second statement is still a second statement
        'SELECT 1 ; SET statement_timeout = 0', 'SELECT 1; SELECT 2', 'SELECT 1; SELECT 2',
        # #7576: whitespace and comments between a U& token and UESCAPE
        'SET U&"statement!005ftimeout" /**/ UESCAPE \'!\' = 0', 'SET U&"statement!005ftimeout" -- c\n UESCAPE \'!\' = 0',
        'SET U&"lock!005ftimeout" /* a */ /* b */ UESCAPE \'!\' TO 0',
        "SELECT U&\"set!005fconfig\" /**/ UESCAPE '!' ('statement_timeout', '0', false)",
        "SELECT U&\"set!005fconfig\"\n\t UESCAPE '!' ('x', '0', false)",
        "SELECT U&'statement!005ftimeout' /**/ UESCAPE '!'",
        'SELECT U&"x" /**/ UESCAPE \'\'', 'SELECT U&"x" UESCAPE "!"', 'SELECT U&"x" UESCAPE 1',
        # #7577: every literal prefix whose end depends on standard_conforming_strings
        "SELECT N'\\' ; SELECT 'second statement ran'; --'", "SELECT n'a\\'; SELECT 2'; SELECT 3",
        "SELECT 'a\\'; SELECT 2'; SELECT 3", "SELECT E'a\\'; SELECT 2'; SELECT 3",
        "SELECT U&'a\\'; SELECT 2'; SELECT 3'", "SELECT N'a'\n'\\'; SELECT 2'; SELECT 3",
        # #7578: the parameter spelling of SET SESSION AUTHORIZATION / SET ROLE
        "SET session_authorization = 'postgres'", 'RESET session_authorization', 'SET "session_authorization" TO DEFAULT',
        'SET LOCAL Session_Authorization TO x', 'SET U&"session!005fauthorization" UESCAPE \'!\' TO x',
        "SELECT 1 AS session_authorization", 'SET role = x', 'RESET role', "SELECT 'role'", 'ALTER ROLE x SET role = y',
        # #7579: pg_settings is writable through its rules
        "UPDATE pg_catalog.pg_settings SET setting = '0' WHERE name = 'statement_timeout'",
        "UPDATE pg_settings SET setting = '0'", 'SELECT * FROM "PG_SETTINGS"', 'SELECT * FROM pg_catalog."pg_settings"',
        'SELECT U&"pg!005fsettings" UESCAPE \'!\'', 'SELECT pg_reload_conf()', 'SELECT pg_catalog.pg_reload_conf()',
        'ALTER SYSTEM SET statement_timeout = 0', 'ALTER SYSTEM RESET ALL', 'alter/**/system set x = 1',
        "ALTER SYSTEM SET work_mem = '1GB'", 'ALTER "SYSTEM" RESET x',
        # the whole timeout family, in every identifier spelling, and as a string
        'SET idle_in_transaction_session_timeout = 0', 'SET idle_session_timeout TO 0', 'SET transaction_timeout = 0',
        'RESET "Transaction_Timeout"', 'ALTER ROLE x SET idle_session_timeout = 0',
        'ALTER DATABASE d SET transaction_timeout TO 0', "SELECT 'statement_timeout'", "SELECT 'LOCK_TIMEOUT'",
        "SELECT E'statement\\x5ftimeout'", "SELECT E'statement\\137timeout'", "SELECT E'statement\\u005ftimeout'",
        "SELECT 'statement\\137timeout'", "SELECT U&'statement\\005ftimeout'", 'SELECT $$lock_timeout$$',
        'SELECT $t$transaction_timeout$t$', "SELECT 'statement_'\n'timeout'", "SELECT 'statement_' -- c\n 'timeout'",
        "SELECT E'statement_'\n'timeout'", "SELECT current_setting('statement_timeout')",
        "SELECT set_config('idle_session_timeout', '0', false)", "SELECT 'set_config'", "SELECT U&'set_config'",
        'SELECT 1 AS "role"', 'SELECT 1 AS "Role"',
        # DISCARD in any form, DO, RESET ALL
        'DISCARD TEMP', 'DISCARD PLANS', 'discard/**/sequences', 'DISCARD -- c\r ALL', 'RESET -- c\r ALL',
        'DO $$ BEGIN NULL; END $$', 'SET SESSION AUTHORIZATION postgres', 'SET LOCAL SESSION AUTHORIZATION x',
        # E strings continue in E mode: the escaped quote hides nothing, the real end is the last quote
        "SELECT E'a'\n'b\\'; SELECT 2'; SELECT 3",
    ]
    MENTION_ALLOWED = [
        # server-rejected spellings that are not bypasses (non-ASCII spaces are identifier bytes)
        'SET search_path = public', 'SELECT 1 AS statement_timeout', 'SET statement_timeout = 0',
        "SELECT 'statement_' 'timeout'", "SELECT 'statement' || '_timeout' AS x_timeout",
        'SELECT 1 AS statement_timeouts', 'SELECT 1 AS my_role', 'SELECT 1 AS roles', 'SELECT 1 AS pg_settings2',
        # literal forms: B'' and X'' end at the first quote (no doubling, no backslash escape, scan.l xb/xh)
        "SELECT B'0101'", "SELECT X'1f'", "SELECT B'0''1'", "SELECT b'1'\n'0'", "SELECT B'0\\'",
        # quote continuation keeps the mode: an E literal continues as an E literal
        "SELECT E'a'\n'b\\'c'", "SELECT 'a'\n'b'", "SELECT 'a' -- c\n 'b'", "SELECT N'a'", "SELECT n'it''s'",
        "SELECT U&'a'\n'b'", 'SELECT 1 -- c\r\nFROM (SELECT 1) t',
        # the escape character of a U& token is read through whitespace and comments
        'SELECT U&"x\\0041" /**/ UESCAPE \'!\'', "SELECT U&'d!0061t' UESCAPE '!'",
        'SELECT 1 AS uescape', 'SELECT 1 AS "uescape"',
    ]
    # #7703: PostgreSQL keeps only the low byte of an octal escape, so a value above 0o377 can decode differently in the
    # guard (a character above U+00FF) and on the server. The guard refuses it (fail closed); 0o377 itself is allowed.
    OCTAL_REFUSED_7703 = [
        "SELECT E'\\563tatement_timeout'", "SELECT E'\\554ock_timeout'", "SELECT E'\\400'", "SELECT E'\\777'",
        "SELECT e'a\\4000b'", "SELECT '\\563'", "SELECT E'a'\n'\\563'", "SELECT E'\\1' || E'\\563'",
    ]
    OCTAL_ALLOWED_7703 = [
        "SELECT E'\\377'", "SELECT E'\\101'", "SELECT E'\\0'", "SELECT E'\\x41'", "SELECT E'\\377abc'", "SELECT E'\\37'",
        "SELECT E'\\3777'",
    ]

    def test_psql_guard_refuses_an_octal_escape_above_0o377_7703(self):
        for sql in self.OCTAL_REFUSED_7703:
            with self.subTest(refused=sql):
                outcome, text, rec = self._guard_outcome(sql)
                self.assertEqual(outcome, 'refused')
                self.assertIn('octal escape above \\377', text)
                self.assertEqual(rec.calls, [], 'psql was not started')

    def test_psql_guard_allows_octal_escapes_up_to_0o377_7703(self):
        for sql in self.OCTAL_ALLOWED_7703:
            with self.subTest(allowed=sql):
                outcome, text, rec = self._guard_outcome(sql)
                self.assertEqual((outcome, text), ('ran', ''))

    def test_octal_boundary_values_7703(self):
        self.assertEqual(pib._decode_e('\\377'), 'ÿ')
        with self.assertRaises(pib.WrapperError) as ctx:
            pib._decode_e('\\400')
        self.assertIn('octal escape above \\377', str(ctx.exception))

    # #7717: a plain-literal '\563' is refused too (a backslash may escape under standard_conforming_strings=off); the
    # error says "literal" and names the E-string case only when the literal is an E-string.
    OCTAL_TEXT_7717 = ('refusing SQL with %s octal escape above \\377 (PostgreSQL keeps only the low byte; the guard '
                       'cannot read it the same way) (%s)')

    def test_octal_refusal_text_names_the_literal_kind_7717(self):
        for sql, kind in (("SELECT E'\\563'", 'an E-string'), ("SELECT '\\563'", 'a plain-literal')):
            with self.subTest(sql=sql):
                outcome, text, rec = self._guard_outcome(sql)
                self.assertEqual(outcome, 'refused')
                self.assertEqual(text, self.OCTAL_TEXT_7717 % (kind, "'\\\\563'"))
                self.assertEqual(rec.calls, [])

    def test_plain_literal_octal_refusal_is_documented_7717(self):
        source = SCRIPT.read_text(encoding='utf-8')
        doc = (SCRIPT.parents[2] / 'docs' / 'ci' / 'PG-ISOLATION.md').read_text(encoding='utf-8')
        for text in (source, doc):
            self.assertIn("plain literal such as '\\563'", text)
        self.assertIn('plain literal', pib._plain_literal.__doc__)

    # #7704: the guard cannot read a function or procedure body, so it refuses CREATE [OR REPLACE] FUNCTION,
    # CREATE [OR REPLACE] PROCEDURE and CALL in every case and whitespace form, as it refuses DO.
    BODY_REFUSED_7704 = [
        ('CREATE FUNCTION', 'CREATE FUNCTION f() RETURNS int LANGUAGE sql AS $$ SELECT 1 $$'),
        ('CREATE FUNCTION', 'create function f() RETURNS int LANGUAGE sql AS $$ SELECT 1 $$'),
        ('CREATE FUNCTION', 'Create Or Replace Function public.f() RETURNS int LANGUAGE sql AS $$ SELECT 1 $$'),
        ('CREATE FUNCTION', 'CREATE\n\tOR\r\nREPLACE\fFUNCTION f() RETURNS int LANGUAGE sql AS $$ SELECT 1 $$'),
        ('CREATE FUNCTION', 'CREATE/**/OR/**/REPLACE/**/FUNCTION f() RETURNS int LANGUAGE sql AS $$ SELECT 1 $$'),
        ('CREATE FUNCTION', 'CREATE -- c\nFUNCTION f() RETURNS int LANGUAGE sql AS $$ SELECT 1 $$'),
        ('CREATE PROCEDURE', 'CREATE PROCEDURE p() LANGUAGE sql AS $$ SELECT 1 $$'),
        ('CREATE PROCEDURE', 'create procedure p() LANGUAGE sql AS $$ SELECT 1 $$'),
        ('CREATE PROCEDURE', 'CREATE OR REPLACE PROCEDURE p() LANGUAGE sql AS $$ SELECT 1 $$'),
        ('CREATE PROCEDURE', 'CREATE\nOR\nREPLACE\nPROCEDURE p() LANGUAGE sql AS $$ SELECT 1 $$'),
        ('CREATE PROCEDURE', 'CREATE/**/PROCEDURE p() LANGUAGE sql AS $$ SELECT 1 $$'),
        ('CALL', 'CALL p()'),
        ('CALL', 'call p()'),
        ('CALL', 'CaLl\np()'),
        ('CALL', '/* c */ CALL p()'),
        ('CALL', '-- c\nCALL p()'),
        ('CALL', 'CALL public.p(1, 2)'),
        ('CALL', 'CALL\t"p"()'),
    ]
    BODY_ALLOWED_7704 = [
        'CREATE TABLE t (call int, function text, procedure int)', 'SELECT 1 AS call', 'SELECT 1 AS "function"',
        "SELECT 'CALL p()'", "SELECT 'create function f()'", 'CREATE DATABASE "ai_memory_t_r1_2" TEMPLATE "ai_memory_x_tpl"',
        'CREATE EXTENSION IF NOT EXISTS age', 'CREATE SCHEMA r7704', 'CREATE VIEW v AS SELECT 1 AS call',
        'SELECT function, procedure FROM t',
    ]

    def test_psql_guard_refuses_create_function_create_procedure_and_call_7704(self):
        for statement, sql in self.BODY_REFUSED_7704:
            with self.subTest(refused=sql):
                outcome, text, rec = self._guard_outcome(sql)
                self.assertEqual(outcome, 'refused')
                self.assertIn(statement, text)
                self.assertIn('refus', text)
                self.assertEqual(rec.calls, [], 'psql was not started')

    def test_psql_guard_allows_what_merely_names_call_function_or_procedure_7704(self):
        for sql in self.BODY_ALLOWED_7704:
            with self.subTest(allowed=sql):
                outcome, text, rec = self._guard_outcome(sql)
                self.assertEqual((outcome, text), ('ran', ''))

    # Every SQL text the module's own callers hand to psql() (connection_budget, mint, drop, session_count,
    # _proved_absent, setup, _names, teardown, sweep) and the live-test helpers: none may be refused.
    REAL_CALLER_SHAPES = [
        ("SELECT current_setting('max_connections')::int, current_setting('superuser_reserved_connections')::int, "
         "coalesce(current_setting('reserved_connections', true)::int, 0), (SELECT count(*) FROM pg_stat_activity)"),
        'CREATE DATABASE "ai_memory_t_r1_2" TEMPLATE "ai_memory_x_tpl"',
        'DROP DATABASE IF EXISTS "ai_memory_t_r1_2"',
        "SELECT count(*) FROM pg_stat_activity WHERE datname = 'ai_memory_t_r1_2'",
        "SELECT 1 FROM pg_database WHERE datname = 'ai_memory_x_tpl'",
        'CREATE DATABASE "ai_memory_x_tpl"',
        'CREATE EXTENSION IF NOT EXISTS age', 'CREATE EXTENSION IF NOT EXISTS vector',
        'ALTER DATABASE "ai_memory_x_tpl" WITH IS_TEMPLATE true ALLOW_CONNECTIONS false',
        'ALTER DATABASE "ai_memory_x_tpl" WITH IS_TEMPLATE false',
        "SELECT datname FROM pg_database WHERE starts_with(datname, 'ai_memory_t_r1_')",
        'SELECT extract(epoch FROM now())::bigint',
        ("SELECT d.datname FROM pg_database d WHERE starts_with(d.datname, 'ai_memory_t_') "
         "AND NOT EXISTS (SELECT 1 FROM pg_stat_activity a WHERE a.datname = d.datname)"),
        'SELECT rolsuper OR rolcreaterole FROM pg_catalog.pg_roles WHERE rolname = current_user',
        'SELECT pg_sleep(60) /* r8cap0123456789 */',
        "SELECT count(*) FROM pg_stat_activity WHERE query LIKE '%r8cap0123456789%' AND pid <> pg_backend_pid()",
        "SELECT count(*) FROM pg_catalog.pg_locks WHERE locktype = 'advisory' AND objid = 7519001 AND granted",
        'SELECT pg_advisory_lock(7519001)', 'SELECT current_database()',
        "SELECT count(*) FROM pg_database WHERE starts_with(datname, 'ai_memory_t_r1_')",
        "SELECT count(*) FROM pg_database WHERE datname = 'ai_memory_x_tpl'",
    ]

    def _guard_outcome(self, sql):
        rec = Recorder(lambda argv, kw: Result(0, 'ok', ''))
        with unittest.mock.patch.object(pib.subprocess, 'run', rec):
            try:
                pib.psql(BASE, sql, tuples=True)
            except pib.WrapperError as exc:
                return 'refused', str(exc), rec
        return 'ran', '', rec

    def test_psql_guard_refuses_any_mention_of_a_cap_control_7575_7576_7577_7578_7579(self):
        for sql in self.MENTION_REFUSED:
            with self.subTest(refused=sql):
                outcome, text, rec = self._guard_outcome(sql)
                self.assertEqual(outcome, 'refused')
                self.assertIn('refus', text)
                self.assertEqual(rec.calls, [], 'psql was not started')

    def test_psql_guard_allows_what_the_server_reads_as_harmless_7575_7576_7577(self):
        for sql in self.MENTION_ALLOWED:
            with self.subTest(allowed=sql):
                outcome, text, rec = self._guard_outcome(sql)
                self.assertEqual((outcome, text), ('ran', ''))
                self.assertEqual(rec.calls[0][0][-1], sql)

    def test_psql_guard_allows_every_real_caller_shape_7578_7579(self):
        for sql in self.REAL_CALLER_SHAPES:
            with self.subTest(real=sql[:60]):
                outcome, text, rec = self._guard_outcome(sql)
                self.assertEqual((outcome, text), ('ran', ''))
                self.assertEqual(rec.calls[0][0][-1], sql)

    def test_effective_timeouts_helper_is_argument_fixed_and_not_a_guard_hole_7579(self):
        # the one read that names pg_settings and the timeouts: psql() refuses it, the helper runs it
        with self.assertRaises(pib.WrapperError):
            pib._refuse_uncapped_sql(pib._EFFECTIVE_TIMEOUTS_SQL)
        rec = Recorder(lambda argv, kw: Result(0, '290000/285000\n', ''))
        with unittest.mock.patch.object(pib.subprocess, 'run', rec):
            self.assertEqual(pib.effective_timeouts(BASE), ('290000', '285000'))
        argv = rec.calls[0][0]
        self.assertEqual(argv[-1], pib._EFFECTIVE_TIMEOUTS_SQL)
        self.assertIn('DO $cap$', argv[argv.index('-c') + 1] if '-c' in argv else '')
        import inspect
        self.assertEqual(list(inspect.signature(pib.effective_timeouts).parameters), ['url'])

    # --- #7615 / #7616 ---------------------------------------------------------------------------------------------
    GUARD_TIMING_CHILD = (
        'import importlib.util, sys, time\n'
        'spec = importlib.util.spec_from_file_location("pib_timing", sys.argv[1])\n'
        'm = importlib.util.module_from_spec(spec); sys.modules["pib_timing"] = m; spec.loader.exec_module(m)\n'
        'kind, n = sys.argv[2], int(sys.argv[3])\n'
        'sql = {"whitespace": "SELECT 1" + " " * n, "quotes": "\'" * n, "comment_open": "/*" * n,\n'
        '       "dash_cr": "--\\r" * n, "dollar": "$a$" * n,\n'
        '       "continue_indent": "SELECT \'a\'\\n" + " " * n + "x",\n'
        '       "continue_comments": "SELECT \'a\'" + " --\\n" * n + "x"}[kind]\n'
        'start = time.monotonic()\n'
        'try:\n'
        '    m._refuse_uncapped_sql(sql)\n'
        'except m.WrapperError:\n'
        '    pass\n'
        'print(time.monotonic() - start)\n')
    GUARD_TIMING_CASES = [
        ('whitespace', 10000), ('quotes', 10000), ('comment_open', 10000), ('dash_cr', 10000), ('dollar', 10000),
        ('continue_indent', 5000), ('continue_comments', 5000),
    ]
    GUARD_TIMING_LIMIT_SECS = 1.0
    GUARD_TIMING_KILL_SECS = 15.0

    def _guard_seconds(self, kind, size):
        """Seconds the guard takes on one hostile input, measured in a child process the parent can kill: a
        super-linear regex holds the GIL, so an in-process timer could never fire."""
        try:
            done = subprocess.run([sys.executable, '-I', '-c', self.GUARD_TIMING_CHILD, str(SCRIPT), kind, str(size)],
                                  capture_output=True, text=True, timeout=self.GUARD_TIMING_KILL_SECS, check=False)
        except subprocess.TimeoutExpired:
            return float('inf')
        self.assertEqual(done.returncode, 0, done.stderr)
        return float(done.stdout.strip())

    def test_guard_finishes_hostile_inputs_in_linear_time_7615(self):
        for kind, size in self.GUARD_TIMING_CASES:
            with self.subTest(kind=kind, size=size):
                self.assertLess(self._guard_seconds(kind, size), self.GUARD_TIMING_LIMIT_SECS)

    def test_guard_refuses_sql_over_the_size_cap_before_tokenising_7615(self):
        cap = pib.GUARD_SQL_MAX_BYTES
        self.assertGreater(cap, 10000)
        pib._refuse_uncapped_sql('SELECT 1' + ' ' * (cap - len('SELECT 1')))
        for over in ('SELECT 1' + ' ' * (cap - len('SELECT 1') + 1), 'SELECT 1 -- ' + 'é' * (cap // 2)):
            with self.subTest(size=len(over)):
                outcome, text, rec = self._guard_outcome(over)
                self.assertEqual(outcome, 'refused')
                self.assertIn('refus', text)
                self.assertIn(str(cap), text)
                self.assertEqual(rec.calls, [], 'psql was not started')

    REGEX_TIMING_CHILD = (
        'import importlib.util, sys, time\n'
        'spec = importlib.util.spec_from_file_location("pib_regex_timing", sys.argv[1])\n'
        'm = importlib.util.module_from_spec(spec); sys.modules["pib_regex_timing"] = m; spec.loader.exec_module(m)\n'
        'pattern = getattr(m, sys.argv[2])\n'
        'text = sys.stdin.buffer.read().decode("utf-8")\n'
        'worst = 0.0\n'
        'for method in ("match", "search", "fullmatch"):\n'
        '    start = time.monotonic()\n'
        '    getattr(pattern, method)(text)\n'
        '    worst = max(worst, time.monotonic() - start)\n'
        'print(worst)\n')
    REGEX_TIMING_BUDGET_SECS = 0.25
    REGEX_TIMING_KILL_SECS = 15.0

    def _worst_over(self, script, name, generators):
        worst = 0.0
        for generator in generators:
            worst = max(worst, self._regex_seconds(name, generator(pib.GUARD_SQL_MAX_BYTES), script))
        return worst

    def _regex_seconds(self, name, text, script=SCRIPT):
        # Worst seconds over match, search and fullmatch of one module regex on one input, measured in a child
        # process the parent can kill (a super-linear regex holds the GIL, so an in-process timer could never fire).
        try:
            done = subprocess.run([sys.executable, '-I', '-c', self.REGEX_TIMING_CHILD, str(script), name],
                                  input=text.encode('utf-8'), capture_output=True, timeout=self.REGEX_TIMING_KILL_SECS,
                                  check=False)
        except subprocess.TimeoutExpired:
            return float('inf')
        self.assertEqual(done.returncode, 0, done.stderr.decode('utf-8', 'replace'))
        return float(done.stdout.decode('utf-8').strip())

    def _module_patterns(self):
        return sweep_patterns(vars(pib))

    def test_module_regexes_equal_the_pinned_table_7615_7653(self):
        """The regexes of pg_isolated_binary.py are PINNED, not detected: the set of (pattern, flags) must equal
        PINNED_REGEXES, so a new, changed or removed regex fails until a reviewer updates the table and its linearity
        reason. This test pins and times regexes; it does not claim to detect super-linearity in general."""
        source = SCRIPT.read_text(encoding='utf-8')
        self.assertEqual(regex_audit_problems(source, self._module_patterns(), PINNED_REGEXES), [])

    def test_each_pinned_regex_finishes_its_worst_case_input_under_budget_7615_7653(self):
        by_key = {(p.pattern, p.flags): name for name, p in self._module_patterns().items()}
        for pattern, flags, reason, generators in PINNED_REGEXES:
            with self.subTest(pattern=pattern):
                self.assertTrue(reason.strip(), 'a pinned regex needs a one-line linearity reason')
                self.assertGreaterEqual(len(generators), 2, 'a pinned regex needs a list of hostile inputs (#7675)')
                for generator in generators:
                    text = generator(pib.GUARD_SQL_MAX_BYTES)
                    self.assertLessEqual(len(text.encode('utf-8', 'surrogatepass')), 4 * pib.GUARD_SQL_MAX_BYTES)
                worst = self._worst_over(SCRIPT, by_key[(pattern, flags)], generators)
                self.assertLess(worst, self.REGEX_TIMING_BUDGET_SECS)

    def _load_copy(self, source):
        """Write `source` (the module plus a planted change) under the scratch dir, import it as a throwaway module
        and return (module, path): every red test below changes a COPY of the module, never the module itself."""
        folder = scratch_dir()
        self.addCleanup(shutil.rmtree, folder, True)
        path = Path(folder) / 'pib_copy.py'
        path.write_text(source, encoding='utf-8')
        name = 'pib_copy_' + uuid.uuid4().hex
        spec = importlib.util.spec_from_file_location(name, str(path))
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        self.addCleanup(sys.modules.pop, name, None)
        spec.loader.exec_module(module)
        return module, path

    def _audit(self, source):
        module, _path = self._load_copy(source)
        return regex_audit_problems(source, sweep_patterns(vars(module)), PINNED_REGEXES)

    def _real_source(self):
        return SCRIPT.read_text(encoding='utf-8')

    def test_the_unchanged_module_has_no_problem_and_the_collector_folds_the_real_patterns_7701(self):
        source = self._real_source()
        self.assertEqual(self._audit(source), [])
        found, problems = static_regex_calls(source)
        self.assertEqual(problems, [])
        folded = {pattern for _attr, pattern in found}
        self.assertEqual(folded, {p.pattern for p in self._module_patterns().values()})
        self.assertIn('^ai_memory_t_([a-z0-9]{1,20})_([0-9]{10})_([0-9a-f]{8})$', folded)
        self.assertIn('^[a-z0-9]{1,20}$', folded)
        self.assertIn('^[A-Za-z0-9_]{1,63}$', folded)

    def test_a_new_compile_fails_the_pin_7701(self):
        problems = self._audit(self._real_source() + "\n_NEW_RE = re.compile(r'zz[0-9]q')\n")
        self.assertEqual(problems, ["not pinned: 'zz[0-9]q' flags 32"])

    def test_a_changed_pattern_fails_the_pin_7701(self):
        source = self._real_source()
        old = "_HEX_RE = re.compile(r'[0-9A-Fa-f]+')"
        self.assertIn(old, source)
        problems = self._audit(source.replace(old, "_HEX_RE = re.compile(r'[0-9A-Fa-g]+')"))
        self.assertEqual(problems, ["not pinned: '[0-9A-Fa-g]+' flags 32", "pinned but absent: '[0-9A-Fa-f]+' flags 32"])

    def test_a_changed_flag_fails_the_pin_as_keyword_and_inline_7701(self):
        source = self._real_source()
        old = "_HEX_RE = re.compile(r'[0-9A-Fa-f]+')"
        self.assertIn(old, source)
        absent = "pinned but absent: '[0-9A-Fa-f]+' flags 32"
        for label, new, expected in (
                ('keyword', "_HEX_RE = re.compile(r'[0-9A-Fa-f]+', flags=re.IGNORECASE)", "not pinned: '[0-9A-Fa-f]+' flags 34"),
                ('positional', "_HEX_RE = re.compile(r'[0-9A-Fa-f]+', re.IGNORECASE)", "not pinned: '[0-9A-Fa-f]+' flags 34"),
                ('inline', "_HEX_RE = re.compile(r'(?i)[0-9A-Fa-f]+')", "not pinned: '(?i)[0-9A-Fa-f]+' flags 34")):
            with self.subTest(flag=label):
                self.assertEqual(self._audit(source.replace(old, new)), [expected, absent])

    def test_a_flag_inside_an_allowed_compile_is_reported_by_the_exact_text_7701(self):
        source = self._real_source()
        for extra, expected in (
                ("_FLAGGED_RE = re.compile(r'zz[0-9]q', re.IGNORECASE)", "not pinned: 'zz[0-9]q' flags 34"),
                ("_FLAGGED_RE = re.compile(r'zz[0-9]q', re.IGNORECASE | re.MULTILINE)", "not pinned: 'zz[0-9]q' flags 42")):
            with self.subTest(extra=extra):
                self.assertEqual(self._audit(source + '\n' + extra + '\n'), [expected])

    def test_a_removed_row_fails_the_pin_7701(self):
        source = self._real_source()
        patterns = self._module_patterns()
        removed = {k: v for k, v in patterns.items() if k != '_HEX_RE'}
        self.assertEqual(regex_audit_problems(source, removed, PINNED_REGEXES),
                         ["pinned but absent: '[0-9A-Fa-f]+' flags 32"])

    NON_LITERAL_7701 = (
        ('name', "_V = 'a'\n_NL_RE = re.compile(_V)\n"),
        ('concatenation', "_NL_RE = re.compile('a' + 'b')\n"),
        ('f-string', "_V = 'a'\n_NL_RE = re.compile(f'{_V}b')\n"),
        ('unknown constant', "_UNK = int('3')\n_NL_RE = re.compile('a{1,%d}' % _UNK)\n"),
        ('expression operand', "_NL_RE = re.compile('a{1,%d}' % (1 + 2))\n"),
        ('keyword pattern', "_NL_RE = re.compile(pattern='a')\n"),
        ('parameter in a function', "def _h(x):\n    return re.compile(x)\n"),
        ('match with a parameter', "def _h(x):\n    return re.match(x, 'a')\n"),
        ('computed in a function', "def _h(x):\n    return re.compile('a' + x)\n"),
        ('format of a parameter', "def _h(n):\n    return re.compile('a{1,%d}' % n)\n"),
        ('del after the compile (#7718)', "_K = 20\n_NL_RE = re.compile('a{1,%d}' % _K)\ndel _K\n"),
    ) + tuple(
        (label, prefix + "_NL_RE = re.compile('a{1,%d}' % _K)\n") for label, prefix in (
            ('augmented assignment (#7718)', "_K = 20\n_K *= 1000\n"),
            ('global rebind in a function (#7718)', "_K = 20\ndef _rebind():\n    global _K\n    _K = 20000\n"),
            ('second module assignment (#7718)', "_K = 20\n_K = 30\n"),
            ('for target (#7718)', "_K = 20\nfor _K in (1, 2):\n    pass\n"),
            ('with target (#7718)', "_K = 20\nwith __import__('contextlib').nullcontext(30) as _K:\n    pass\n"),
            ('except target (#7718)', "_K = 20\ntry:\n    pass\nexcept OSError as _K:\n    pass\n"),
            ('walrus (#7718)', "_K = 20\n(_K := 5)\n"),
            ('global only (#7718)', "_K = 20\ndef _g():\n    global _K\n"),
        ))

    def test_a_pattern_that_is_not_a_foldable_literal_fails_closed_7701(self):
        source = self._real_source()
        for label, extra in self.NON_LITERAL_7701:
            with self.subTest(pattern=label):
                problems = self._audit(source + '\n' + extra)
                self.assertTrue(any(re.fullmatch(r'line \d+: re\.(compile|match) pattern is not a string literal or a '
                                                 r'%-format of module constants', p) for p in problems), problems)

    def test_a_percent_format_of_module_constants_is_folded_not_refused_7701(self):
        found, problems = static_regex_calls("N = 3\nP = 'ab'\n_X_RE = re.compile('^%s{1,%d}$' % (P, N))\n")
        self.assertEqual((found, problems), ([('compile', '^ab{1,3}$')], []))
        found, problems = static_regex_calls("_X_RE = re.compile('a%d%d' % (1,))\n")
        self.assertEqual(found, [])
        self.assertEqual(len(problems), 1, problems)

    OUTSIDE_MODULE_LEVEL_7701 = (
        ('function', "def _h():\n    return re.compile(r'[0-9]+')\n"),
        ('list element', "_P = [re.compile(r'[0-9]+')]\n"),
        ('if body', "if True:\n    _P = re.compile(r'[0-9]+')\n"),
        ('class attribute', "class _C:\n    P = re.compile(r'[0-9]+')\n"),
        ('call argument', "_P = id(re.compile(r'[0-9]+'))\n"),
        ('default argument', "def _h(p=re.compile(r'[0-9]+')):\n    return p\n"),
    )

    def test_a_pattern_compiled_outside_a_module_level_assignment_fails_7701(self):
        source = self._real_source()
        for label, extra in self.OUTSIDE_MODULE_LEVEL_7701:
            with self.subTest(place=label):
                problems = self._audit(source + '\n' + extra)
                self.assertTrue(any(re.fullmatch(r'line \d+: re\.compile outside a module-level assignment', p)
                                    for p in problems), problems)

    def test_a_call_on_an_unpinned_literal_fails_7701(self):
        problems = self._audit(self._real_source() + "\ndef _h(x):\n    return re.match(r'zz', x)\n")
        self.assertTrue(any(re.fullmatch(r"line \d+: re\.match pattern not pinned: 'zz'", p) for p in problems), problems)

    def test_a_pattern_held_where_the_static_collector_cannot_see_it_is_caught_by_the_sweep_7701(self):
        source = self._real_source()
        for label, extra in (
                ('plain global', "_HIDDEN = getattr(re, 'comp' + 'ile')(r'zz[0-9]q')\n"),
                ('list', "_HIDDEN = [getattr(re, 'comp' + 'ile')(r'zz[0-9]q')]\n"),
                ('dict', "_HIDDEN = {'k': getattr(re, 'comp' + 'ile')(r'zz[0-9]q')}\n")):
            with self.subTest(held=label):
                found, static_problems = static_regex_calls(source + '\n' + extra)
                self.assertEqual(static_problems, [], 'the static collector must not see it, only the sweep')
                self.assertEqual(self._audit(source + '\n' + extra), ["not pinned: 'zz[0-9]q' flags 32"])

    # #7714: `from re import ...` and `import re as <alias>` are ordinary spellings of re, so the collector fails closed
    # on any import of re other than a plain top-level `import re`, and on sre_compile, sre_parse and _sre.
    IMPORT_REFUSED_7714 = (
        ('from re import match', "from re import match\ndef _h(s):\n    return match(r'(a+)+$', s)\n"),
        ('from re import compile', "from re import compile\ndef _h():\n    return compile(r'(a+)+$')\n"),
        ('from re import compile as c', "from re import compile as c\n_X_RE = c(r'(a+)+$')\n"),
        ('import re as alias', "import re as _alias\ndef _h(s):\n    return _alias.match(r'(a+)+$', s)\n"),
        ('import in a function', "def _h():\n    import re\n    return re\n"),
        ('from re import star', "from re import *\n"),
        ('import sre_compile', "import sre_compile\n"),
        ('import sre_parse as sp', "import sre_parse as sp\n"),
        ('from sre_compile import compile', "from sre_compile import compile\n"),
        ('import _sre', "import _sre\n"),
        ('from re.x import y', "from re.x import y\n"),
    )

    def test_an_import_of_re_other_than_plain_import_re_fails_closed_7714(self):
        source = self._real_source()
        for label, extra in self.IMPORT_REFUSED_7714:
            with self.subTest(spelling=label):
                _found, problems = static_regex_calls(source + '\n' + extra)
                self.assertTrue(any(re.fullmatch(r'line \d+: import of (re|sre_compile|sre_parse|_sre)\b.*', p)
                                    for p in problems), problems)

    def test_a_plain_top_level_import_re_is_accepted_7714(self):
        found, problems = static_regex_calls("import re\n_X_RE = re.compile('a')\n")
        self.assertEqual((found, problems), ([('compile', 'a')], []))

    def test_the_reviewer_reproductions_fail_the_audit_7714(self):
        source = self._real_source()
        for label, extra in self.IMPORT_REFUSED_7714[:4]:
            with self.subTest(spelling=label):
                self.assertNotEqual(regex_audit_problems(source + '\n' + extra, sweep_patterns(vars(pib)), PINNED_REGEXES),
                                    [])

    def test_plain_then_aliased_import_fails_the_full_audit_7805(self):
        source = self._real_source() + (
            "\nimport re, re as _alias\ndef _h(s):\n    return _alias.match(r'zz7805', s)\n")
        self.assertTrue(any('import of re other than a plain top-level' in problem
                            for problem in self._audit(source)))

    def test_aliased_then_plain_import_fails_the_full_audit_7805(self):
        source = self._real_source() + (
            "\nimport re as _alias, re\ndef _h(s):\n    return _alias.match(r'zz7805', s)\n")
        self.assertTrue(any('import of re other than a plain top-level' in problem
                            for problem in self._audit(source)))

    def test_plain_combined_imports_pass_the_full_audit_7805(self):
        for extra in ('import re, os', 'import os, re', 'import re, re'):
            with self.subTest(spelling=extra):
                self.assertEqual(self._audit(self._real_source() + '\n' + extra + '\n'), [])

    def test_separate_aliased_imports_fail_the_full_audit_7805(self):
        for extra in ('import re\nimport re as _alias', 'import re as _alias\nimport re'):
            with self.subTest(spelling=extra):
                source = self._real_source() + '\n' + extra + (
                    "\ndef _h(s):\n    return _alias.match(r'zz7805', s)\n")
                self.assertTrue(any('import of re other than a plain top-level' in problem
                                    for problem in self._audit(source)))

    # #7715: flags are read from the positional slot and the keyword of every re.<fn> signature; a non-constant flags
    # argument fails closed; a non-compile call is pinned as a (pattern, flags) pair.
    FLAGS_REFUSED_7715 = (
        ('match positional', "def _h(s):\n    return re.match(r'[0-9]+', s, re.VERBOSE)\n"),
        ('match keyword', "def _h(s):\n    return re.match(r'[0-9]+', s, flags=re.X)\n"),
        ('search positional', "def _h(s):\n    return re.search(r'[0-9]+', s, re.I)\n"),
        ('fullmatch keyword', "def _h(s):\n    return re.fullmatch(r'[0-9]+', s, flags=re.M | re.S)\n"),
        ('findall positional', "def _h(s):\n    return re.findall(r'[0-9]+', s, re.A)\n"),
        ('finditer keyword', "def _h(s):\n    return re.finditer(r'[0-9]+', s, flags=re.I)\n"),
        ('sub positional', "def _h(s):\n    return re.sub(r'[0-9]+', '', s, 0, re.I)\n"),
        ('subn keyword', "def _h(s):\n    return re.subn(r'[0-9]+', '', s, flags=re.I)\n"),
        ('split positional', "def _h(s):\n    return re.split(r'[0-9]+', s, 0, re.I)\n"),
        ('integer flags', "def _h(s):\n    return re.match(r'[0-9]+', s, 64)\n"),
    )
    FLAGS_NON_CONSTANT_7715 = (
        ('match name', "def _h(s, f):\n    return re.match(r'[0-9]+', s, f)\n"),
        ('match keyword name', "def _h(s, f):\n    return re.match(r'[0-9]+', s, flags=f)\n"),
        ('compile name', "_F = 2\n_X_RE = re.compile(r'zz', _F)\n"),
        ('compile keyword call', "_X_RE = re.compile(r'zz', flags=int('2'))\n"),
        ('sub name', "def _h(s, f):\n    return re.sub(r'[0-9]+', '', s, 0, f)\n"),
        ('star args', "def _h(s, a):\n    return re.match(r'[0-9]+', *a)\n"),
        ('double star', "def _h(s, k):\n    return re.match(r'[0-9]+', s, **k)\n"),
    )

    def test_a_non_compile_call_with_unpinned_flags_fails_the_pin_7715(self):
        source = self._real_source()
        for label, extra in self.FLAGS_REFUSED_7715:
            with self.subTest(call=label):
                problems = self._audit(source + '\n' + extra)
                self.assertTrue(any(re.fullmatch(r"line \d+: re\.\w+ pattern '\[0-9\]\+' not pinned with flags \d+", p)
                                    for p in problems), problems)

    def test_the_exact_7702_reproduction_fails_the_pin_7715(self):
        problems = self._audit(self._real_source() + "\ndef _h(s):\n    return re.match(r'[0-9]+', s, re.VERBOSE)\n")
        self.assertEqual(len(problems), 1, problems)
        self.assertRegex(problems[0], r"^line \d+: re\.match pattern '\[0-9\]\+' not pinned with flags 96$")

    def test_a_non_compile_call_on_a_pinned_pair_is_accepted_7715(self):
        source = self._real_source()
        for extra in ("def _h(s):\n    return re.match(r'[0-9]+', s)\n",
                      "def _h(s):\n    return re.match(r'[0-9]+', s, re.UNICODE)\n",
                      "def _h(s):\n    return re.match(r'[0-9]+', s, flags=re.U)\n"):
            with self.subTest(extra=extra):
                self.assertEqual(self._audit(source + '\n' + extra), [])

    def test_a_non_constant_flags_argument_fails_closed_7715(self):
        source = self._real_source()
        for label, extra in self.FLAGS_NON_CONSTANT_7715:
            with self.subTest(call=label):
                _found, problems = static_regex_calls(source + '\n' + extra)
                self.assertTrue(any(re.fullmatch(r'line \d+: re\.\w+ flags is not a constant', p) for p in problems),
                                problems)

    # #7716: the audit is the union of the static collector and the runtime sweep: a static compile with no swept
    # object (del, overwrite) is reported.
    def test_a_static_compile_that_the_sweep_no_longer_sees_is_reported_7716(self):
        source = self._real_source()
        for label, extra, expected in (
                ('del of an unpinned compile', "_T_RE = re.compile(r'(a+)+$')\n_t_match = _T_RE.match\ndel _T_RE\n",
                 "compiled but not pinned (not swept): '(a+)+$' flags 32"),
                ('overwrite of an unpinned compile', "_T_RE = re.compile(r'(a+)+$')\n_T_RE = None\n",
                 "compiled but not pinned (not swept): '(a+)+$' flags 32"),
                ('del of a pinned object', "del _HEX_RE\n",
                 "pinned but absent: '[0-9A-Fa-f]+' flags 32")):
            with self.subTest(case=label):
                module, _path = self._load_copy(source + '\n' + extra)
                self.assertNotIsInstance(vars(module).get('_T_RE' if 'T_RE' in extra else '_HEX_RE'), re.Pattern)
                problems = regex_audit_problems(source + '\n' + extra, sweep_patterns(vars(module)), PINNED_REGEXES)
                self.assertIn(expected, problems)

    # #7713: restore a pin for CodeQL alert 524 (py/import-and-import-from) without regex internals.
    IMPORT_CLASH_SAMPLES_7713 = (
        ("import os\nfrom os import path\n", ['os']),
        ("import os.path\nfrom os.path import join\n", ['os.path']),
        ("from a import b\ndef f():\n    import a\n", ['a']),
        ("import os\nfrom pathlib import Path\n", []),
        ("import unittest.mock\nfrom unittest import mock\n", []),
        ("import os as o\nfrom os import path\n", ['os']),
    )

    def test_the_import_form_detector_flags_a_module_imported_both_ways_7713(self):
        for source, expected in self.IMPORT_CLASH_SAMPLES_7713:
            with self.subTest(source=source):
                self.assertEqual(import_form_clashes(source), expected)

    def test_the_test_module_and_the_guard_module_never_import_one_module_both_ways_7653_7713(self):
        for path in (Path(__file__), SCRIPT):
            self.assertEqual(import_form_clashes(path.read_text(encoding='utf-8')), [],
                             '%s imports a module both as `import X` and as `from X import`' % path.name)

    def test_a_copy_of_the_test_module_that_imports_one_module_both_ways_fails_red_7713(self):
        source = Path(__file__).read_text(encoding='utf-8')
        self.assertEqual(import_form_clashes(source), [])
        self.assertEqual(import_form_clashes(source + '\nfrom pathlib import PurePath\nimport pathlib\n'),
                         ['pathlib'])

    def test_a_slow_pattern_is_over_the_timing_budget_7701(self):
        extra = "\n_SLOW_RE = re.compile(r'(a+)+$')\n"
        _module, path = self._load_copy(self._real_source() + extra)
        worst = self._worst_over(path, '_SLOW_RE', (lambda _n: 'a' * 26 + '!',))
        self.assertGreaterEqual(worst, self.REGEX_TIMING_BUDGET_SECS)
        self.assertLess(self._worst_over(SCRIPT, '_HEX_RE', (_pad('', 'a'),)), self.REGEX_TIMING_BUDGET_SECS)

    def test_pinned_rows_carry_lists_of_hostile_inputs_7675(self):
        by_pattern = {row[0]: row[3] for row in PINNED_REGEXES}
        digits = by_pattern[r'[0-9]+']
        dollar = by_pattern[r'\$(?:[A-Za-z_\x80-\U0010ffff][A-Za-z0-9_\x80-\U0010ffff]*)?\$']
        self.assertIn('a' * 64, [g(64) for g in digits])
        self.assertIn('$1' * 32, [g(64) for g in dollar])

    CONCAT_SAMPLES_7633 = (
        ("X = ['a' 'b']\n", [1]),
        ("X = [f'a' f'b']\n", [1]),
        ("X = [f'a' 'b']\n", [1]),
        ("X = ['a' f'b']\n", [1]),
        ("X = {f'a{1}' f'b'}\n", [1]),
        ("X = [\n    f'a'\n    f'b'\n]\n", [3]),
        ("X = [f'a', f'b']\n", []),
        ("X = (f'a' f'b')\n", []),
        ("X = [f'{1}', 'b']\n", []),
        ("X = [f'{1 + 2}']\n", []),
    )

    def test_implicit_concatenation_scan_sees_f_strings_7633(self):
        for source, expected in self.CONCAT_SAMPLES_7633:
            with self.subTest(source=source):
                self.assertEqual(implicit_concat_lines(source.encode('utf-8')), expected)

    def test_no_implicit_string_concatenation_inside_a_list_or_set_7616(self):
        for path in (Path(__file__), SCRIPT):
            found = implicit_concat_lines(path.read_bytes())
            self.assertEqual(found, [], '%s joins string literals implicitly inside a list or set' % path.name)

    def test_unquoted_identifiers_fold_ascii_only_and_whitespace_is_the_scanner_set_7575(self):
        self.assertEqual(pib._tokenise('SELECT K'), [(pib._IDENT, 'select k')])
        self.assertEqual(pib._tokenise('A\f\vB'), [(pib._IDENT, 'a'), (pib._IDENT, 'b')])
        self.assertEqual(pib._tokenise('a --x\rb'), [(pib._IDENT, 'a'), (pib._IDENT, 'b')])
        self.assertEqual(pib._tokenise('a --x\nb'), [(pib._IDENT, 'a'), (pib._IDENT, 'b')])
        self.assertEqual(pib._tokenise('K'), [(pib._IDENT, 'K')])

    def test_role_cell_skips_without_createrole_unless_the_live_flag_is_set_7552(self):
        cell = LiveEndToEnd('test_role_and_role_in_database_defaults_are_kept_7522')
        env = {k: v for k, v in os.environ.items() if k != LIVE_REQUIRED_VAR}
        with unittest.mock.patch.object(pib, 'psql', lambda *a, **k: 'f\n'), \
                unittest.mock.patch.dict(os.environ, dict(env, **{pib.URL_VAR: BASE}), clear=True):
            with self.assertRaises(unittest.SkipTest):
                cell.test_role_and_role_in_database_defaults_are_kept_7522()
            for value in ('0', ''):
                with unittest.mock.patch.dict(os.environ, {LIVE_REQUIRED_VAR: value}):
                    with self.assertRaises(unittest.SkipTest):
                        cell.test_role_and_role_in_database_defaults_are_kept_7522()
            with unittest.mock.patch.dict(os.environ, {LIVE_REQUIRED_VAR: '1'}):
                with self.assertRaises(AssertionError) as ctx:
                    cell.test_role_and_role_in_database_defaults_are_kept_7522()
                self.assertNotIsInstance(ctx.exception, unittest.SkipTest)
                self.assertIn('CREATEROLE', str(ctx.exception))

    def test_connect_budget_refusal_shows_the_floored_timeout_and_a_useful_hint_7554(self):
        def refusal(url):
            addrs = [(0, 0, 0, '', ('192.0.2.%d' % n, 5432)) for n in range(1, 181)]
            with unittest.mock.patch.object(pib.socket, 'getaddrinfo', return_value=addrs):
                with self.assertRaises(pib.WrapperError) as ctx:
                    pib.server_caps_sql(pib._pg_env(url))
            return str(ctx.exception)
        host = 'postgres://%s' + '\x40' + 'db.example:5432/d'
        floored = refusal(host % 'u' + '?connect_timeout=1')
        self.assertIn('connect_timeout 2 s', floored)
        self.assertIn('floored', floored)
        self.assertIn('1 s', floored)
        self.assertIn('sslmode=require', floored)
        plain = refusal(host % 'u' + '?connect_timeout=5')
        self.assertNotIn('floored', plain)
        self.assertIn('sslmode=require', plain)
        for mode in ('require', 'verify-ca', 'verify-full'):
            text = refusal(host % 'u' + '?connect_timeout=1&sslmode=' + mode)
            with self.subTest(sslmode=mode):
                self.assertNotIn('or set sslmode', text)
                self.assertIn('sslmode=' + mode, text)
                self.assertIn('hostaddr', text)

    def test_connect_budget_hint_floors_only_below_two_seconds_and_stops_offering_a_useless_lower_7580(self):
        def refusal(query):
            addrs = [(0, 0, 0, '', ('192.0.2.%d' % n, 5432)) for n in range(1, 181)]
            with unittest.mock.patch.object(pib.socket, 'getaddrinfo', return_value=addrs):
                with self.assertRaises(pib.WrapperError) as ctx:
                    pib.server_caps_sql(pib._pg_env('postgres://u' + '\x40' + 'db.example:5432/d?' + query))
            return str(ctx.exception)
        padded = refusal('connect_timeout=05')
        self.assertIn('connect_timeout 5 s', padded)
        self.assertNotIn('floored', padded)
        self.assertNotIn('05', padded)
        one = refusal('connect_timeout=1')
        self.assertIn('connect_timeout 2 s, floored from 1 s', one)
        self.assertNotIn('lower connect_timeout', one)
        self.assertIn('hostaddr', one)
        self.assertIn('sslmode=require', one)
        zero_padded_one = refusal('connect_timeout=01')
        self.assertIn('floored from 1 s', zero_padded_one)
        self.assertNotIn('lower connect_timeout', zero_padded_one)
        at_floor = refusal('connect_timeout=2')
        self.assertNotIn('floored', at_floor)
        self.assertNotIn('lower connect_timeout', at_floor)
        self.assertIn('hostaddr', at_floor)
        for mode, passes_two in (('allow', True), ('prefer', True), ('disable', False)):
            above = refusal('connect_timeout=5&sslmode=' + mode)
            floor = refusal('connect_timeout=1&sslmode=' + mode)
            with self.subTest(sslmode=mode):
                self.assertIn('lower connect_timeout', above)
                self.assertNotIn('lower connect_timeout', floor)
                self.assertIn('hostaddr', floor)
                self.assertEqual('or set sslmode=require' in floor, passes_two)
                self.assertEqual('or set sslmode=require' in above, passes_two)

    def test_connect_budget_refusal_names_budget_addresses_and_sslmode_7523(self):
        six = [(0, 0, 0, '', ('192.0.2.%d' % n, 5432)) for n in range(1, 7)]
        user, secret = 'secret' + 'user', 'hunter' + '2'
        url = 'postgres://' + ':'.join((user, secret)) + '\x40' + 'db.example:5432/d'
        with unittest.mock.patch.object(pib.socket, 'getaddrinfo', return_value=six):
            with self.assertRaises(pib.WrapperError) as ctx:
                pib.server_caps_sql(pib._pg_env(url))
        text = str(ctx.exception)
        for needle in ('360', 'connect_timeout 30', '6 address', 'sslmode=prefer', 'sslmode=require'):
            self.assertIn(needle, text)
        for private in (secret, user, 'db.example', '192.0.2'):
            self.assertNotIn(private, text)

    def test_options_ending_in_a_backslash_are_refused_7455(self):
        for value in ('-c%20search_path%3Dab%5C', '%5C%5C%5C'):
            with self.subTest(value=value), self.assertRaises(pib.WrapperError) as ctx:
                pib._pg_env(BASE + '&options=' + value)
            self.assertIn("'options'", str(ctx.exception))
            self.assertIn('backslash', str(ctx.exception))
        # an escaped (doubled) trailing backslash is fine
        pib._pg_env(BASE + '&options=-c%20search_path%3Dab%5C%5C')
        called = []
        with unittest.mock.patch.object(pib.subprocess, 'run', Recorder(lambda a, k: called.append(a) or Result())):
            with self.assertRaises(pib.WrapperError):
                pib.psql(BASE + '&options=ab%5C', 'SELECT 1')
        self.assertEqual(called, [], 'refused before psql runs')

    def test_hold_session_has_no_server_caps_7456(self):
        with Patched():
            hold = pib.open_hold(BASE)
        self.assertNotIn('-c', hold.argv)
        self.assertNotIn('statement_timeout', ' '.join(hold.argv))
        self.assertNotIn('statement_timeout', hold.kw['env'].get('PGOPTIONS', ''))
        self.assertNotIn('lock_timeout', hold.kw['env'].get('PGOPTIONS', ''))
        rec = Recorder(lambda argv, kw: Result(0, '', ''))
        with unittest.mock.patch.object(pib.subprocess, 'run', rec):
            pib.psql(BASE, 'SELECT 1')
        self.assertIn('statement_timeout', ' '.join(rec.calls[0][0]))
        self.assertIn('NO server-side', pib.open_hold.__doc__)

    def test_unknown_reason_wording_7448(self):
        refused = {'CREATE DATABASE': 'ERROR:  permission denied to create database'}

        def text(pg):
            with self.assertRaises(pib.WrapperError) as ctx:
                self.run_setup(pg)
            return str(ctx.exception), ctx.exception.returncode

        # a timed-out CREATE: its own wording, never "status None"
        inner = FakePg()

        def timing_out(argv, kw):
            if 'CREATE DATABASE' in argv[-1]:
                raise subprocess.TimeoutExpired(argv, 1)
            return inner(argv, kw)
        with unittest.mock.patch.object(pib.subprocess, 'run', Recorder(timing_out)):
            with self.assertRaises(pib.WrapperError) as ctx:
                pib.setup(BASE, self.DB, 8)
        msg = str(ctx.exception)
        self.assertIsNone(ctx.exception.returncode)
        self.assertIn('outcome is unknown', msg)
        self.assertIn('psql timed out, so the server may still commit the statement', msg)
        self.assertNotIn('status None', msg)
        self.assertNotIn('not a plain SQL error', msg)
        self.assertFalse([s for s in inner.log if s.startswith(('ALTER', 'DROP', 'CREATE EXT'))])
        for status in (2, 3):
            with self.subTest(status=status):
                msg, rc = text(FakePg(lost=('CREATE DATABASE',), lost_status=status))
                self.assertIn('psql ended with status %d, not a plain SQL error' % status, msg)
                self.assertEqual(rc, status)
        msg, _ = text(FakePg({TPL: {'template': False, 'sessions': 0}}, fail=refused))
        self.assertIn('the existence check found a database with this name', msg)
        self.assertNotIn('not a plain SQL error', msg)
        msg, _ = text(FakePg(fail=dict(refused, **{'SELECT 1 FROM pg_database': 'ERROR:  check-failed'})))
        self.assertIn('the existence check itself failed', msg)
        self.assertNotIn('not a plain SQL error', msg)

    def test_empty_stderr_is_spelled_out_7406(self):
        silent = lambda argv, kw: Result(-9, '', '')
        with unittest.mock.patch.object(pib.subprocess, 'run', Recorder(silent)):
            with self.assertRaises(pib.WrapperError) as ctx:
                pib.psql(BASE, 'SELECT 1')
        self.assertEqual(str(ctx.exception), 'psql failed (-9): no stderr')

    def test_template_limit_counts_utf8_bytes_not_characters_7373(self):
        fits = 'é' * 29 + 'x'      # 29*2 + 1 = 59 bytes, 30 characters
        over = 'é' * 30            # 60 bytes, 30 characters
        self.assertEqual(len(fits.encode('utf-8')), 59)
        self.assertEqual(pib.template_name(fits), fits + '_tpl')
        with self.assertRaises(pib.WrapperError) as ctx:
            pib.template_name(over)
        text = str(ctx.exception)
        self.assertIn('is 60 bytes', text)
        self.assertIn('63-byte identifier limit', text)

    def test_owned_setup_then_teardown_leaves_nothing(self):
        pg = FakePg()
        tpl = self.run_setup(pg)
        self.assertEqual(tpl, TPL)
        self.assertEqual(pg.dbs, {TPL: {'template': True, 'sessions': 0}})
        self.assertFalse([s for s in pg.log if s.startswith('DROP')], 'setup never drops on success')
        with unittest.mock.patch.object(pib.subprocess, 'run', Recorder(pg)):
            pib.teardown(BASE, self.DB, RUN)
        self.assertEqual(pg.dbs, {})
        self.assertFalse([s for s in pg.log if 'FORCE' in s])

    def test_failure_after_create_drops_only_the_template_it_created(self):
        other = {'template': True, 'sessions': 0}
        pg = FakePg({'unrelated_tpl': dict(other)}, fail={'CREATE EXTENSION': 'ERROR:  no age'})
        with self.assertRaises(pib.WrapperError) as ctx:
            self.run_setup(pg)
        self.assertIn('no age', str(ctx.exception), 'the primary error is preserved')
        self.assertEqual(pg.dbs, {'unrelated_tpl': other})
        self.assertEqual(pg.touched('unrelated_tpl'), [])
        self.assertFalse([s for s in pg.log if 'FORCE' in s])

    def test_overlong_names_that_would_truncate_onto_one_template_are_refused(self):
        a = 'x' * 59 + 'A'
        b = 'x' * 59 + 'B'
        pg = FakePg()
        for name in (a, b, 'x' * 63):
            with self.assertRaises(pib.WrapperError):
                self.run_setup(pg, name)
        self.assertEqual(pg.log, [], 'refused before any statement reaches the server')
        self.assertEqual(pib.template_name('x' * 59), 'x' * 59 + '_tpl')
        with self.assertRaises(pib.WrapperError):
            pib.template_name(a)


class RunOne(unittest.TestCase):
    def test_cargo_runs_against_held_clone_then_clone_is_dropped(self):
        r = runner()
        with Patched() as rec:
            rc = r.run_one(['--test', 'foo_6383'], isolate=True)
        self.assertEqual(rc, 0)
        cargo = FakePopen.cargo()
        self.assertEqual(len(cargo), 1)
        self.assertEqual(cargo[0].argv, ['cargo', 'test', '--no-fail-fast', '--test', 'foo_6383', '--',
                                         '--test-threads=1'])
        self.assertTrue(cargo[0].kw.get('start_new_session'), 'children get their own process group')
        minted = pib.database_name(cargo[0].kw['env'][pib.URL_VAR])
        self.assertEqual(pib.parse_isolated_name(minted, RUN) is not None, True, minted)
        holds = [p for p in FakePopen.instances if p.is_hold]
        self.assertEqual(len(holds), 1, 'one keepalive session per clone')
        self.assertEqual(holds[0].kw['env']['PGDATABASE'], minted)
        self.assertNotIn('postgres://', ' '.join(holds[0].argv))
        sql = rec.sql()
        self.assertTrue(sql[0].startswith('CREATE DATABASE'))
        self.assertEqual(sql[-1], 'DROP DATABASE IF EXISTS "%s"' % minted)

    def test_hold_that_never_appears_fails_closed_without_running_cargo(self):
        def answer(argv, kw):
            sql = argv[-1]
            if 'count(*)' in sql:
                return Result(0, '0\n')
            return Result()
        r = runner()
        with Patched(Recorder(answer)), unittest.mock.patch.object(pib.time, 'monotonic',
                                                           side_effect=[0.0] + [1e6] * 50):
            rc = r.run_one(['--test', 'foo'], isolate=True)
        self.assertEqual(rc, pib.EXIT_MINT)
        self.assertEqual(FakePopen.cargo(), [])

    def test_mint_failure_fails_closed_without_running_cargo(self):
        r = runner()
        with Patched(Recorder(lambda a, k: Result(1, '', 'ERROR: boom'))):
            rc = r.run_one(['--test', 'foo'], isolate=True)
        self.assertEqual(rc, pib.EXIT_MINT)
        self.assertEqual(FakePopen.cargo(), [])

    def test_residual_runs_on_shared_database_with_flag_stripped(self):
        # Review r1 M1: the Rust helper must not mint for a residual binary.
        r = runner()
        with Patched() as rec:
            rc = r.run_one(['--test', 'a2a_campaign_round1'], isolate=False)
        self.assertEqual(rc, 0)
        self.assertEqual(rec.sql(), [], 'nothing minted for a residual binary')
        env = FakePopen.cargo()[0].kw['env']
        self.assertEqual(env[pib.URL_VAR], BASE)
        self.assertNotIn(pib.FLAG_VAR, env)

    def test_isolated_child_keeps_template_variable(self):
        r = runner()
        with Patched():
            r.run_one(['--test', 'foo'], isolate=True)
        self.assertEqual(FakePopen.cargo()[0].kw['env'][pib.TEMPLATE_VAR], TPL)


class PerBinaryLogs(unittest.TestCase):
    """Review r1 M3: output goes to a per-binary file, tailed on failure."""

    def test_output_is_written_to_a_file_in_the_log_dir(self):
        d = scratch_dir()
        r = runner(log_dir=d)
        with Patched():
            r.run_one(['--test', 'foo_6383'], isolate=True)
        out = FakePopen.cargo()[0].kw['stdout']
        self.assertEqual(Path(out.name).parent, Path(d))
        self.assertEqual(Path(out.name).name, 'foo_6383.log')
        self.assertIn('test result: ok', (Path(d) / 'foo_6383.log').read_text())
        self.assertEqual(FakePopen.cargo()[0].kw.get('stderr'), subprocess.STDOUT)

    def test_failure_prints_a_group_with_the_log_tail(self):
        d = scratch_dir()
        r = runner(log_dir=d)
        printed = []
        with Patched(), unittest.mock.patch.object(pib, '_out', printed.append):
            FakePopen.cargo_rc = 101
            FakePopen.cargo_output = ''.join('line %d\n' % i for i in range(500)) + 'test result: FAILED.\n'
            rc = r.run_one(['--test', 'bad'], isolate=True)
        text = '\n'.join(printed)
        self.assertEqual(rc, 101)
        self.assertIn('::group::', text)
        self.assertIn('test result: FAILED.', text)
        self.assertIn('line 499', text)
        self.assertNotIn('line 100\n', text + '\n', 'only the tail is echoed')

    def test_success_prints_only_the_result_lines(self):
        r = runner()
        printed = []
        with Patched(), unittest.mock.patch.object(pib, '_out', printed.append):
            FakePopen.cargo_output = 'noise\ntest result: ok. 3 passed; 0 failed\n'
            r.run_one(['--test', 'good'], isolate=True)
        text = '\n'.join(printed)
        self.assertNotIn('::group::', text)
        self.assertNotIn('noise', text)
        self.assertIn('test result: ok. 3 passed', text)


class Pool(unittest.TestCase):
    def test_width_is_capped_at_eight(self):
        self.assertEqual(pib.clamp_jobs(100), 8)
        self.assertEqual(pib.clamp_jobs(3), 3)
        with self.assertRaises(pib.WrapperError):
            pib.clamp_jobs(0)

    def test_run_all_returns_worst_exit_code_and_runs_residual_after_pool(self):
        order = []
        r = runner()

        def fake_run_one(target, isolate=True):
            order.append((target[1], isolate))
            return 101 if target[1] == 'bad' else 0
        targets = [['--test', 'a'], ['--test', 'bad'], ['--test', 'res'], ['--test', 'b']]
        with unittest.mock.patch.object(r, 'run_one', fake_run_one):
            rc = r.run_all(targets, {'res'})
        self.assertEqual(rc, 101)
        self.assertEqual(sorted(n for n, _ in order), ['a', 'b', 'bad', 'res'])
        self.assertEqual(order[-1], ('res', False), 'residual runs last, on the shared database')

    def test_run_all_with_no_targets_fails_closed(self):
        with self.assertRaises(pib.WrapperError):
            runner().run_all([], set())


class Termination(unittest.TestCase):
    """Review r1 M2: SIGTERM stops dispatch, kills children, drops clones."""

    def test_terminate_stops_pool_kills_children_and_drops_clone(self):
        r = runner(width=1)
        targets = [['--test', 'b%d' % i] for i in range(4)]
        result = {}
        with Patched() as rec:
            FakePopen.block = threading.Event()
            started = threading.Event()
            real_init = FakePopen.__init__

            def init(self, argv, **kw):
                real_init(self, argv, **kw)
                if not self.is_hold:
                    started.set()
            killed = []

            def killpg(pgid, sig):
                killed.append((pgid, sig))
                for p in FakePopen.cargo():
                    p.returncode = -sig
                FakePopen.block.set()
            with unittest.mock.patch.object(FakePopen, '__init__', init), \
                    unittest.mock.patch.object(pib.os, 'killpg', killpg):
                t = threading.Thread(target=lambda: result.setdefault('rc', r.run_all(targets, {'b3'})))
                t.start()
                self.assertTrue(started.wait(10), 'the first child started')
                r.terminate()
                t.join(15)
        self.assertFalse(t.is_alive())
        self.assertEqual(result['rc'], pib.EXIT_TERM)
        self.assertEqual(len(FakePopen.cargo()), 1, 'no binary is dispatched after the stop')
        self.assertIn(signal.SIGTERM, [s for _, s in killed])
        creates = [s for s in rec.sql() if s.startswith('CREATE DATABASE')]
        drops = [s for s in rec.sql() if s.startswith('DROP DATABASE')]
        self.assertEqual(len(creates), 1)
        self.assertEqual(len(drops), 1, 'the running clone is dropped before exit')

    def test_signal_children_permission_error_is_visible_7892(self):
        r = runner(width=1)
        r._children[4242] = object()
        err = io.StringIO()
        with unittest.mock.patch.object(pib.os, 'killpg', side_effect=PermissionError(1, 'denied')), \
                contextlib.redirect_stderr(err):
            r._signal_children(signal.SIGTERM)
        self.assertIn('4242', err.getvalue())
        self.assertIn('SIGTERM', err.getvalue())

    def test_signal_children_broken_stderr_keeps_signalling_7915(self):
        r = runner(width=1)
        r._children[4242] = object()
        r._children[4243] = object()

        class BrokenStderr:
            def write(self, text):
                raise BrokenPipeError(32, 'broken pipe')

        with unittest.mock.patch.object(pib.os, 'killpg', side_effect=PermissionError(1, 'denied')) as kp, \
                unittest.mock.patch.object(pib.sys, 'stderr', BrokenStderr()):
            r._signal_children(signal.SIGTERM)
        self.assertEqual(kp.call_count, 2, 'a dead stderr must not skip the remaining children')
        self.assertEqual([c.args[0] for c in kp.call_args_list], [4242, 4243])

    def test_signal_children_process_lookup_error_is_silent_7892(self):
        r = runner(width=1)
        r._children[4242] = object()
        r._children[4243] = object()
        err = io.StringIO()
        with unittest.mock.patch.object(pib.os, 'killpg', side_effect=ProcessLookupError()) as kp, \
                contextlib.redirect_stderr(err):
            r._signal_children(signal.SIGTERM)
        self.assertEqual(err.getvalue(), '')
        self.assertEqual(kp.call_count, 2, 'the best-effort loop continues')

    def test_main_installs_term_and_int_handlers_for_run(self):
        src = SCRIPT.read_text()
        self.assertTrue('signal.SIGTERM' in src, 'SIGTERM handler')
        self.assertTrue('signal.SIGINT' in src, 'SIGINT handler')
        self.assertFalse('sys.exit(143)' in src, 'a bare exit leaks children and clones')


class MainRun(unittest.TestCase):
    """Review r1 C1/L2: ``run`` parses --url and works end to end."""

    def write_targets(self, *names):
        d = scratch_dir()
        p = Path(d) / 'targets.txt'
        p.write_text(''.join('--test %s\n' % n for n in names))
        return d, p

    def test_run_help_lists_its_flags(self):
        done = subprocess.run([sys.executable, str(SCRIPT), 'run', '--help'], capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stderr)
        for flag in ('--url', '--run-id', '--template', '--log-dir', '--targets-file', '--jobs'):
            self.assertIn(flag, done.stdout)

    def test_main_run_with_url_flag_runs_and_returns_zero(self):
        d, targets = self.write_targets('one', 'two')
        env = {pib.FLAG_VAR: '1'}
        with Patched() as rec, unittest.mock.patch.dict(os.environ, env), \
                unittest.mock.patch.object(pib.signal, 'signal'):
            rc = pib.main(['run', '--url', BASE, '--run-id', RUN, '--template', TPL,
                           '--targets-file', str(targets), '--log-dir', d, '--jobs', '2',
                           '--', 'cargo', 'test', '--no-fail-fast'])
        self.assertEqual(rc, 0)
        self.assertEqual(len(FakePopen.cargo()), 2)
        self.assertEqual(len([s for s in rec.sql() if s.startswith('CREATE DATABASE')]), 2)
        self.assertEqual(len([s for s in rec.sql() if s.startswith('DROP DATABASE')]), 2)

    def test_run_is_refused_unless_opted_in(self):
        d, targets = self.write_targets('one')
        argv = ['run', '--url', BASE, '--run-id', RUN, '--template', TPL, '--targets-file', str(targets),
                '--log-dir', d, '--', 'cargo', 'test']
        for env in ({}, {pib.FLAG_VAR: '0'}, {pib.FLAG_VAR: '1', pib.KILL_VAR: '1'}):
            clean = {k: v for k, v in os.environ.items() if k not in (pib.FLAG_VAR, pib.KILL_VAR)}
            clean.update(env)
            with Patched(), unittest.mock.patch.dict(os.environ, clean, clear=True):
                self.assertEqual(pib.main(list(argv)), pib.EXIT_USAGE, env)
            self.assertEqual(FakePopen.cargo(), [], env)

    def test_run_requires_template_and_run_id(self):
        d, targets = self.write_targets('one')
        for missing in ('--template', '--run-id'):
            argv = ['run', '--url', BASE, '--run-id', RUN, '--template', TPL, '--targets-file',
                    str(targets), '--log-dir', d, '--', 'cargo', 'test']
            i = argv.index(missing)
            del argv[i:i + 2]
            clean = {k: v for k, v in os.environ.items() if k not in (pib.TEMPLATE_VAR, pib.RUN_ID_VAR)}
            clean[pib.FLAG_VAR] = '1'
            with Patched(), unittest.mock.patch.dict(os.environ, clean, clear=True):
                self.assertEqual(pib.main(argv), pib.EXIT_USAGE, missing)


class CiLiveCells(unittest.TestCase):
    def test_ci_runs_the_live_cells_on_the_enterprise_fed_leg_7485(self):
        ci = (SCRIPT.parents[2] / '.github' / 'workflows' / 'ci.yml').read_text()
        start = ci.index('- name: Run the pg_isolated_binary live cells')
        step = ci[start:ci.index('\n      - name:', start + 10)]
        configure = ci.index('- name: Configure enterprise-fed tier')
        self.assertGreater(start, configure, 'runs after the URL is minted')
        self.assertIn("matrix.tier == 'enterprise-fed'", step)
        self.assertIn('AI_MEMORY_TEST_PG_LIVE_REQUIRED: "1"', step)
        self.assertIn('test_pg_isolated_binary.LiveEndToEnd', step)


class NoShell(unittest.TestCase):
    def test_source_never_uses_shell_true_or_tmp(self):
        src = SCRIPT.read_text()
        self.assertIsNone(re.search(r'shell\s*=\s*True', src))
        self.assertFalse('/tmp' in src, 'no /tmp paths')
        self.assertTrue(src.startswith('#!/usr/bin/env python3'))


class PortableLiveCommand(unittest.TestCase):
    def test_7806_live_silent_child_uses_current_python(self):
        """The macOS live cell must not depend on a platform's true path."""
        tree = ast.parse(Path(__file__).read_text())
        live = next(node for node in tree.body
                    if isinstance(node, ast.ClassDef) and node.name == 'LiveEndToEnd')
        command = next(node.value.args[0] for node in ast.walk(live)
                       if isinstance(node, ast.Assign)
                       and any(isinstance(target, ast.Name) and target.id == 'true_run'
                               for target in node.targets))
        separator = next(i for i, node in enumerate(command.elts)
                         if isinstance(node, ast.Constant) and node.value == '--')
        child = command.elts[separator + 1:]
        self.assertIsInstance(child[0], ast.Attribute)
        self.assertEqual(ast.dump(child[0]), ast.dump(ast.parse('sys.executable', mode='eval').body))
        argv = [sys.executable] + [ast.literal_eval(node) for node in child[1:]]
        self.assertEqual(argv, [sys.executable, '-c', 'pass'])
        for target in ('e2e_probe', 'e2e_true'):
            with self.subTest(target=target):
                result = subprocess.run(argv + ['--test', target], capture_output=True,
                                        text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, '')
                self.assertEqual(result.stderr, '')


def _live_url():
    return os.environ.get(pib.URL_VAR, '')


LIVE_REQUIRED_VAR = 'AI_MEMORY_TEST_PG_LIVE_REQUIRED'
_LIVE_READY = bool(_live_url() and shutil.which('psql'))


@unittest.skipUnless(_LIVE_READY or os.environ.get(LIVE_REQUIRED_VAR) == '1',
                     'AI_MEMORY_TEST_POSTGRES_URL unset (live e2e)')
class LiveEndToEnd(unittest.TestCase):
    """C1 end to end: the real script, a real server, a probe, a silent Python child.

    With AI_MEMORY_TEST_PG_LIVE_REQUIRED=1 (set by the CI step that runs these, #7485) a missing URL or psql
    fails the class instead of skipping it."""

    def setUp(self):
        if not _LIVE_READY:
            self.fail('%s=1 but %s or psql is missing' % (LIVE_REQUIRED_VAR, pib.URL_VAR))

    def _live_setting(self, url, options=None, db=None):
        target = pib.with_database(url, db) if db else url
        if options is not None:
            target += ('&' if '?' in target else '?') + 'options=' + urllib.parse.quote(options)
        return list(pib.effective_timeouts(target))

    @staticmethod
    def _admin(url, *statements):
        """Setup DDL outside psql(): the wrapper refuses SET and multi-statement SQL on purpose (#7521)."""
        for sql in statements:
            done = subprocess.run(['psql', '-X', '-q', '-v', 'ON_ERROR_STOP=1', '-c', sql], capture_output=True,
                                  text=True, env=pib._pg_env(url), timeout=60)
            if done.returncode != 0:
                raise AssertionError('%s -> %s' % (sql, done.stderr.strip()))

    @staticmethod
    def _as_role(url, role, password):
        parts = urllib.parse.urlsplit(url)
        host = parts.netloc.rpartition('@')[2]
        netloc = '%s:%s@%s' % (urllib.parse.quote(role, safe=''), urllib.parse.quote(password, safe=''), host)
        return urllib.parse.urlunsplit(parts._replace(netloc=netloc))

    def test_server_resolves_caller_and_default_timeouts_7477_7478_7479_7480_7484(self):
        url = _live_url()
        cap, lock_cap = TemplateOwnership._caps(url)
        # no caller value: the wrapper caps
        self.assertEqual(self._live_setting(url), [str(cap), str(lock_cap)])
        # mixed case, a tighter value: kept, and the lock is clamped below it
        statement, lock = self._live_setting(url, '-c Statement_Timeout=500ms')
        self.assertEqual(statement, '500')
        self.assertLess(int(lock), 500)
        # a looser value and 0 (unlimited) take the cap
        self.assertEqual(self._live_setting(url, '-c statement_timeout=1d')[0], str(cap))
        self.assertEqual(self._live_setting(url, '-c statement_timeout=0')[0], str(cap))
        # forms the wrapper never parses: the server reads them, and the result is never looser than the caller
        for value, limit in (('0x1f4', 500), ('1e3', 1000), ('.5s', 500), ('+500', 500), ('010', 8), ('1.2ms', 1)):
            with self.subTest(value=value):
                try:
                    got = int(self._live_setting(url, '-c statement_timeout=' + value)[0])
                except pib.WrapperError:
                    continue            # the server refused the value: fail closed
                self.assertLessEqual(got, max(limit, 1), value)
        # a stricter database-level default is kept, never overridden with the looser cap
        db = 'ai_memory_cap_%s' % uuid.uuid4().hex[:8]
        pib.psql(url, 'CREATE DATABASE %s' % db)
        try:
            self._admin(url, "ALTER DATABASE %s SET statement_timeout = '1s'" % db)
            statement, lock = self._live_setting(url, db=db)
            self.assertEqual(statement, '1000')
            self.assertLess(int(lock), 1000)
        finally:
            pib.psql(url, 'DROP DATABASE IF EXISTS %s' % db)

    def _session_cap_after(self, url, sql):
        """Run ``sql`` as the middle statement of a three-statement psql session (the wrapper's own cap first, the
        statement, then a read of the cap), keeping going past a server error, and return the cap psql ended with.
        Used only for statements the guard ALLOWS: this is the proof that none of them loosens the cap."""
        argv = ['psql', '-X', '-q', '-At', '-v', 'ON_ERROR_STOP=0', '-c', pib.server_caps_sql(pib._pg_env(url)),
                '-c', sql, '-c', "SELECT 'CAP=' || setting FROM pg_catalog.pg_settings WHERE name = 'statement_timeout'"]
        done = subprocess.run(argv, capture_output=True, text=True, env=pib._pg_env(url), timeout=60)
        return [ln for ln in done.stdout.splitlines() if ln.startswith('CAP=')][-1]

    def test_guard_rows_live_allowed_rows_keep_the_cap_and_refused_rows_never_reach_the_server_7575_7579(self):
        url = _live_url()
        cap, _ = TemplateOwnership._caps(url)
        for sql in TemplateOwnership.MENTION_ALLOWED:
            with self.subTest(allowed=sql):
                pib._refuse_uncapped_sql(sql)                       # the guard allows it
                self.assertEqual(self._session_cap_after(url, sql), 'CAP=%d' % cap)
        reached = []
        real_run = subprocess.run

        def watch(argv, *a, **k):
            reached.append(argv)
            return real_run(argv, *a, **k)
        with unittest.mock.patch.object(pib.subprocess, 'run', watch):
            for sql in TemplateOwnership.MENTION_REFUSED:
                with self.subTest(refused=sql):
                    with self.assertRaises(pib.WrapperError) as ctx:
                        pib.psql(url, sql)
                    self.assertIn('refus', str(ctx.exception))
        self.assertEqual(reached, [], 'a refused statement reached the server')
        # B'' and X'' end at the first quote: the doubled quote is not an escape, the server reads two tokens
        with self.assertRaises(pib.WrapperError) as ctx:
            pib.psql(url, "SELECT B'0''1'")
        self.assertIn('syntax error', str(ctx.exception))
        # and every real caller shape the guard allows is accepted by the server through psql() itself
        self.assertEqual(pib.psql(url, 'SELECT current_database()', tuples=True).strip(),
                         pib._pg_env(url)['PGDATABASE'])

    def test_small_statement_timeout_still_leaves_a_real_lock_wait_7519(self):
        url = _live_url()
        key = 7519000 + int(uuid.uuid4().hex[:4], 16)
        statement, lock = self._live_setting(url, '-c statement_timeout=3s')
        self.assertEqual(statement, '3000')
        self.assertEqual(lock, '1500')               # half, not 1 ms
        holder = subprocess.Popen(
            ['psql', '-X', '-q', '-v', 'ON_ERROR_STOP=1', '-c',
             'SELECT pg_advisory_lock(%d), pg_sleep(1.5)' % key],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, env=pib._pg_env(url))
        try:
            deadline = time.monotonic() + 20
            while pib.psql(url, "SELECT count(*) FROM pg_catalog.pg_locks WHERE locktype = 'advisory' "
                           "AND objid = %d AND granted" % key, tuples=True).strip() == '0':
                self.assertLess(time.monotonic(), deadline, 'the holder never took the lock')
                time.sleep(0.05)
            # a 5 s cap, a ~300 ms wait for the lock: it must succeed, not die on a 1 ms lock_timeout
            pib.psql(url + ('&' if '?' in url else '?') + 'options=' +
                              urllib.parse.quote('-c statement_timeout=5s'),
                              'SELECT pg_advisory_lock(%d)' % key, tuples=True)
        finally:
            holder.communicate(timeout=30)

    def test_shadow_schema_ahead_of_pg_catalog_does_not_skip_the_cap_7520(self):
        url = _live_url()
        cap, lock_cap = TemplateOwnership._caps(url)
        schema = 'r7520_' + uuid.uuid4().hex[:8]
        self._admin(
            url,
            'CREATE SCHEMA %s' % schema,
            "CREATE VIEW %s.pg_settings AS SELECT 'x'::text AS name, '0'::text AS setting" % schema,
            "CREATE FUNCTION %s.set_config(text, text, boolean) RETURNS text LANGUAGE sql AS 'SELECT $2'" % schema)
        try:
            got = self._live_setting(url, '-c search_path=%s,pg_catalog' % schema)
            self.assertEqual(got, [str(cap), str(lock_cap)])
        finally:
            self._admin(url, 'DROP SCHEMA %s CASCADE' % schema)

    def test_role_and_role_in_database_defaults_are_kept_7522(self):
        url = _live_url()
        allowed = pib.psql(url, 'SELECT rolsuper OR rolcreaterole FROM pg_catalog.pg_roles '
                           'WHERE rolname = current_user', tuples=True).strip()
        if allowed != 't':
            message = 'the live role needs CREATEROLE for the role-level cells (%s=1)' % LIVE_REQUIRED_VAR
            if os.environ.get(LIVE_REQUIRED_VAR) == '1':
                self.fail(message)
            self.skipTest(message)
        role = 'r7522_' + uuid.uuid4().hex[:8]
        password = uuid.uuid4().hex
        db = 'ai_memory_cap_%s' % uuid.uuid4().hex[:8]
        self._admin(url, "CREATE ROLE %s LOGIN PASSWORD '%s'" % (role, password), 'CREATE DATABASE %s' % db)
        try:
            self._admin(url, "ALTER ROLE %s SET statement_timeout = '1s'" % role,
                        "ALTER ROLE %s IN DATABASE %s SET statement_timeout = '4s'" % (role, db),
                        "ALTER ROLE %s IN DATABASE %s SET lock_timeout = '1s'" % (role, db))
            as_role = self._as_role(url, role, password)
            statement, lock = self._live_setting(as_role)
            self.assertEqual(statement, '1000')              # role level, tighter than the wrapper cap
            self.assertEqual(lock, '500')
            statement, lock = self._live_setting(as_role, db=db)
            self.assertEqual((statement, lock), ('4000', '1000'))   # role-in-database wins, lock kept
        finally:
            self._admin(url, 'DROP DATABASE IF EXISTS %s' % db, 'DROP ROLE IF EXISTS %s' % role)

    def test_required_flag_turns_a_missing_url_into_a_failure_7485(self):
        env = {k: v for k, v in os.environ.items() if k != pib.URL_VAR}
        env[LIVE_REQUIRED_VAR] = '1'
        done = subprocess.run([sys.executable, '-m', 'unittest', 'test_pg_isolated_binary.LiveEndToEnd'],
                              cwd=str(Path(__file__).resolve().parent), env=env, capture_output=True, text=True)
        self.assertNotEqual(done.returncode, 0)
        self.assertIn('FAILED', done.stderr)
        self.assertIn('missing', done.stderr)

    def test_server_cap_cancels_a_slow_statement_and_leaves_no_backend_7457(self):
        url = _live_url()
        tag = 'r8cap' + uuid.uuid4().hex[:10]
        with unittest.mock.patch.object(pib, 'PSQL_TIMEOUT_SECS', 8.0), \
                unittest.mock.patch.object(pib, '_connect_budget_secs', lambda env: 1), \
                unittest.mock.patch.object(pib, 'PSQL_CAP_MARGIN_SECS', 1.0), \
                unittest.mock.patch.object(pib, 'PSQL_LOCK_GAP_SECS', 0.5):
            started = time.monotonic()
            with self.assertRaises(pib.WrapperError) as ctx:
                pib.psql(url, 'SELECT pg_sleep(60) /* %s */' % tag)
            elapsed = time.monotonic() - started
        self.assertEqual(ctx.exception.returncode, 1, str(ctx.exception))
        self.assertIn('canceling statement due to statement timeout', str(ctx.exception))
        self.assertLess(elapsed, 8.0, 'the server cancelled before the client limit')
        time.sleep(1.5)
        left = pib.psql(url, "SELECT count(*) FROM pg_stat_activity WHERE query LIKE '%%%s%%' "
                        "AND pid <> pg_backend_pid()" % tag, tuples=True).strip()
        self.assertEqual(left, '0', 'no backend still runs the capped statement')

    def test_setup_run_teardown_creates_and_drops_a_clone(self):
        url = _live_url()
        d = Path(scratch_dir())
        db = 'ai_memory_e2e_%s' % uuid.uuid4().hex[:8]
        run_id = 'e' + uuid.uuid4().hex[:10]
        probe = d / 'probe.py'
        probe.write_text(
            'import importlib.util, os, sys\n'
            'spec = importlib.util.spec_from_file_location("pib", %r)\n'
            'm = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)\n'
            'print("PROBE_DB=" + m.psql(os.environ[%r], "SELECT current_database()", tuples=True).strip())\n'
            'print("test result: ok. 1 passed; 0 failed")\n' % (str(SCRIPT), pib.URL_VAR))
        (d / 'targets.txt').write_text('--test e2e_probe\n--test e2e_true\n')
        env = {k: v for k, v in os.environ.items() if not k.startswith('PG')}
        env.update({pib.URL_VAR: url, pib.FLAG_VAR: '1'})
        env.pop(pib.KILL_VAR, None)
        setup = subprocess.run([sys.executable, str(SCRIPT), 'setup', '--db', db, '--jobs', '1',
                                '--run-id', run_id, '--emit-env'], env=env, capture_output=True, text=True)
        self.assertEqual(setup.returncode, 0, setup.stderr)
        emitted = dict(ln.split('=', 1) for ln in setup.stdout.split())
        self.assertEqual(emitted[pib.RUN_ID_VAR], run_id)
        env.update(emitted)
        try:
            probe_run = subprocess.run(
                [sys.executable, str(SCRIPT), 'run', '--targets-file', str(d / 'targets.txt'),
                 '--log-dir', str(d / 'logs'), '--jobs', '1', '--', sys.executable, str(probe)],
                env=env, capture_output=True, text=True, timeout=300)
            self.assertEqual(probe_run.returncode, 0, probe_run.stderr + probe_run.stdout)
            log = (d / 'logs' / 'e2e_probe.log').read_text()
            found = re.search(r'PROBE_DB=(\S+)', log)
            self.assertIsNotNone(found, log)
            clone = found.group(1)
            self.assertIsNotNone(pib.parse_isolated_name(clone, run_id), clone)
            true_run = subprocess.run(
                [sys.executable, str(SCRIPT), 'run', '--targets-file', str(d / 'targets.txt'),
                 '--log-dir', str(d / 'logs2'), '--jobs', '1', '--', sys.executable, '-c', 'pass'],
                env=env, capture_output=True, text=True, timeout=300)
            self.assertEqual(true_run.returncode, 0, true_run.stderr)
            self.assertIn('-> ai_memory_t_%s_' % run_id, true_run.stderr)
            left = pib.psql(url, "SELECT count(*) FROM pg_database WHERE starts_with(datname, '%s')"
                            % ('ai_memory_t_%s_' % run_id), tuples=True).strip()
            self.assertEqual(left, '0', 'every clone of the run was dropped')
        finally:
            down = subprocess.run([sys.executable, str(SCRIPT), 'teardown', '--db', db, '--run-id', run_id],
                                  env=env, capture_output=True, text=True)
            self.assertEqual(down.returncode, 0, down.stderr)
        tpl_left = pib.psql(url, "SELECT count(*) FROM pg_database WHERE datname = '%s_tpl'" % db,
                            tuples=True).strip()
        self.assertEqual(tpl_left, '0', 'teardown dropped the template')



class ConnectTimeout7866(unittest.TestCase):
    """Exercise setup's actual CLI boundary with no real PostgreSQL process."""

    def test_oversized_numeric_cli_is_controlled_without_psql_7866(self):
        directory = Path(scratch_dir())
        try:
            marker = directory / 'psql-called'
            hook = directory / 'sitecustomize.py'
            # The CLI process is real; only its external psql boundary is replaced.
            hook.write_text(
                "import os, subprocess\n"
                "from pathlib import Path\n"
                "original_run = subprocess.run\n"
                "def guarded_run(argv, *args, **kwargs):\n"
                "    if Path(str(argv[0])).name == 'psql':\n"
                "        Path(os.environ['PSQL_MARKER_7866']).write_text('called')\n"
                "        raise AssertionError('unexpected psql invocation')\n"
                "    return original_run(argv, *args, **kwargs)\n"
                "subprocess.run = guarded_run\n")
            for digits in (400, 5000):
                with self.subTest(digits=digits):
                    env = {k: v for k, v in os.environ.items()
                           if not k.startswith(('PG', 'AI_MEMORY_TEST_P', 'CI_PG_'))}
                    env.update(AI_MEMORY_TEST_PG_ISOLATE='1',
                               AI_MEMORY_TEST_POSTGRES_URL=BASE + '&connect_timeout=' + '9' * digits,
                               PYTHONPATH=str(directory), PSQL_MARKER_7866=str(marker))
                    result = subprocess.run(
                        [sys.executable, str(SCRIPT), 'setup', '--db', 'issue7866', '--jobs', '1'],
                        env=env, capture_output=True, text=True, timeout=30)
                    self.assertFalse(marker.exists(), "refusal must precede psql")
                    self.assertEqual(result.returncode, 2, result.stderr[:1000])
                    self.assertNotIn('Traceback', result.stderr)
                    self.assertIn('connect_timeout', result.stderr)
                    self.assertLess(len(result.stderr), 1000)
                    self.assertNotIn('pw', result.stderr)
                    self.assertNotIn('9' * 100, result.stderr)
        finally:
            shutil.rmtree(directory)

    def test_normal_and_long_leading_zero_values_keep_caps_7866(self):
        for value in ('1', '2', '30', '284'):
            with self.subTest(value=value):
                normal = pib._pg_env(BASE + '&connect_timeout=' + value)
                padded = pib._pg_env(BASE + '&connect_timeout=' + '0' * 5000 + value)
                self.assertEqual(pib._connect_plan(padded), pib._connect_plan(normal))
                self.assertEqual(pib.server_caps_sql(padded), pib.server_caps_sql(normal))

    def test_zero_and_cap_boundary_refusals_are_controlled_7866(self):
        for value in ('0', '0' * 5000, '285', '300', '301', '0' * 5000 + '285'):
            with self.subTest(value=value[:20]), self.assertRaises(pib.WrapperError) as caught:
                pib.server_caps_sql(pib._pg_env(BASE + '&connect_timeout=' + value))
            self.assertLess(len(str(caught.exception)), 1000)


if __name__ == '__main__':
    unittest.main()
