#!/usr/bin/env python3
"""Partition the compiled test executables into one serial and two parallel shards (#6344).

Input is the stdout of ``cargo test --no-run --message-format=json`` (or
``json-render-diagnostics``), read from ``--build-json`` or stdin, plus the
repository sources. Output is written to ``--out-dir``:

* ``serial.txt``      class (a): Postgres / ``#[serial]`` / ``federat`` in the name /
                      unknown source. Run at ``--test-threads=1`` in ONE process.
                      Also carries ``--lib`` (the lib unittests filtered to the
                      Postgres test-name prefixes).
* ``parallel_1.txt``  class (b), first half, carries ``--lib`` (the lib unittests
  ``parallel_2.txt``  with ``--skip`` of the same prefixes) in half 1 only.
                      Run at ``--test-threads=3`` each, as two concurrent processes.
* ``lib_pg_filters.txt``  the lib Postgres test-name prefixes (one per line).
* ``manifest.json``   per-executable class, reason and weight; set sizes; estimates.

Every list line is one cargo target selector: ``--lib``, ``--bin NAME``,
``--test NAME`` or ``--example NAME``.

Fail closed (exit 2, ``::error::`` on stderr) when:

* the three sets are not disjoint, or their union is not every executable
  (re-read from the files that were written, so a writer bug is caught too);
* the build output has no test executable at all;
* the lib is present but ``lib_pg_prefixes.txt`` is empty or a src file reads
  ``AI_MEMORY_TEST_POSTGRES_URL`` from a module no prefix covers (a new lib
  Postgres test would otherwise run in a parallel shard against the shared
  database);
* a target name contains a character outside ``[A-Za-z0-9_.-]`` (the shell
  consumer word-splits the lines).

Python 3.9+, standard library only.
"""
import argparse
import json
import re
import sys
from pathlib import Path

# Class (a) evidence. Scout report CI-SHARD-SCOUT-2026-10-09, plus the shared
# lane-database helpers under tests/common that only Postgres cells use.
PG_RE = re.compile(
    r'AI_MEMORY_TEST_POSTGRES_URL|postgres_url\(|postgres_env|PostgresEnv|PgPool'
    r'|sqlx::|PostgresStore|pg_test_client|feature\s*=\s*"sal-postgres"|postgres://'
    r'|pg_barrier|lane_db|pg_sources|pg_blocking_pids'
)
SERIAL_RE = re.compile(r'serial_test|#\[serial')
FEDERAT_RE = re.compile(r'federat', re.IGNORECASE)
# Class (b) binaries carrying these run in the SAME half so two of them never
# run in different processes at once.
PORT_RE = re.compile(r'(?:127\.0\.0\.1|localhost|0\.0\.0\.0):(?!0\b)\d{2,5}\b')
SHARED_PATH_RE = re.compile(r'"/(?:tmp|var/tmp|dev/shm)/')
ENV_RE = re.compile(r'env::set_var|env::remove_var|set_current_dir')
PG_ENV_READ_RE = re.compile(r'var(?:_os)?\(\s*"AI_MEMORY_TEST_POSTGRES_URL"')
SAFE_NAME_RE = re.compile(r'^[A-Za-z0-9_.-]+$')

KIND_FLAG = {'test': '--test', 'bin': '--bin', 'example': '--example', 'bench': '--bench'}
LIB_KINDS = {'lib', 'rlib', 'cdylib', 'staticlib', 'dylib', 'proc-macro'}


class PartitionError(Exception):
    """A fail-closed condition; main() prints it as ::error:: and exits 2."""


class Exe:
    """One compiled test executable."""

    def __init__(self, kind, name, src_path, executable):
        self.kind = kind
        self.name = name
        self.src_path = src_path
        self.executable = executable
        self.cls = None
        self.reasons = []
        self.shared = []

    @property
    def key(self):
        return '%s:%s' % (self.kind, self.name)

    @property
    def selector(self):
        return '--lib' if self.kind == 'lib' else '%s %s' % (KIND_FLAG[self.kind], self.name)


def parse_build_json(lines):
    """Return the unique test executables from cargo's JSON message stream."""
    exes = {}
    for raw in lines:
        raw = raw.strip()
        if not raw.startswith('{'):
            continue
        try:
            msg = json.loads(raw)
        except ValueError:
            continue
        if msg.get('reason') != 'compiler-artifact':
            continue
        executable = msg.get('executable')
        profile = msg.get('profile') or {}
        if not executable or not profile.get('test'):
            continue
        target = msg.get('target') or {}
        kinds = target.get('kind') or []
        if any(k in LIB_KINDS for k in kinds):
            kind = 'lib'
        else:
            kind = next((k for k in kinds if k in KIND_FLAG), None)
        if kind is None:
            raise PartitionError('unrecognised test target kind %r for %s' % (kinds, executable))
        name = target.get('name')
        if not name or not SAFE_NAME_RE.match(name):
            raise PartitionError('unsafe test target name %r' % (name,))
        exes[executable] = Exe(kind, name, target.get('src_path') or '', executable)
    ordered = sorted(exes.values(), key=lambda e: (e.kind, e.name))
    keys = [e.key for e in ordered]
    if len(keys) != len(set(keys)):
        raise PartitionError('two executables share a kind:name key (ambiguous selector)')
    if not ordered:
        raise PartitionError('the build output lists no test executable')
    return ordered


def read_sources(src_path):
    """Source text of a target: its file plus the sibling module directory.

    Returns None when nothing readable exists (unknown source: class a).
    """
    if not src_path:
        return None
    p = Path(src_path)
    files = []
    if p.is_file():
        files.append(p)
    base = p.parent if p.name == 'main.rs' else p.with_suffix('')
    if base.is_dir():
        files.extend(sorted(base.rglob('*.rs')))
    if not files:
        return None
    seen, chunks = set(), []
    for f in files:
        if f in seen:
            continue
        seen.add(f)
        try:
            chunks.append(f.read_text(errors='replace'))
        except OSError:
            return None
    return '\n'.join(chunks)


def classify(exe):
    """Set exe.cls ('a' or 'b'), exe.reasons and exe.shared. Not for the lib."""
    text = read_sources(exe.src_path)
    if text is None:
        exe.cls, exe.reasons = 'a', ['unknown-source']
        return
    reasons = []
    m = PG_RE.search(text)
    if m:
        reasons.append('pg:' + m.group(0)[:32])
    if SERIAL_RE.search(text):
        reasons.append('serial')
    if FEDERAT_RE.search(exe.name):
        reasons.append('name:federat')
    if reasons:
        exe.cls, exe.reasons = 'a', reasons
        return
    exe.cls = 'b'
    if ENV_RE.search(text):
        exe.reasons.append('env')
    if PORT_RE.search(text):
        exe.shared.append('port')
    if SHARED_PATH_RE.search(text):
        exe.shared.append('shared-path')


def module_path_of(src_file, src_root):
    """Lib module path of a file under src/ (store/postgres.rs -> store::postgres)."""
    rel = src_file.relative_to(src_root).with_suffix('')
    parts = list(rel.parts)
    if parts and parts[-1] == 'mod':
        parts = parts[:-1]
    return '::'.join(parts)


def uncovered_lib_pg_modules(src_root, prefixes):
    """Lib modules that read the Postgres test URL but match no prefix."""
    missing = []
    for f in sorted(Path(src_root).rglob('*.rs')):
        if f.name in ('lib.rs', 'main.rs'):
            continue
        try:
            text = f.read_text(errors='replace')
        except OSError:
            continue
        if not PG_ENV_READ_RE.search(text):
            continue
        mod = module_path_of(f, Path(src_root))
        if not any(p in mod or p.startswith(mod) for p in prefixes):
            missing.append(mod)
    return missing


def load_prefixes(path):
    out = []
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if line and not line.startswith('#'):
            out.append(line)
    return out


def load_weights(path):
    try:
        data = json.loads(Path(path).read_text())
        return {str(k): float(v) for k, v in data['weights'].items()}
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise PartitionError('cannot read weight table %s: %s' % (path, exc))


def weight_of(exe, weights, class_mean):
    return weights.get(exe.key, class_mean.get(exe.cls, 0.0))


def class_means(exes, weights):
    sums = {'a': [0.0, 0], 'b': [0.0, 0]}
    for e in exes:
        if e.key in weights and e.cls in sums:
            sums[e.cls][0] += weights[e.key]
            sums[e.cls][1] += 1
    all_s = sum(v[0] for v in sums.values())
    all_n = sum(v[1] for v in sums.values())
    fallback = all_s / all_n if all_n else 0.0
    return {c: (v[0] / v[1] if v[1] else fallback) for c, v in sums.items()}


def balance(items, base1, base2):
    """Greedy longest-first split of (weight, [exes]) items into two halves."""
    h1, h2 = [], []
    t1, t2 = base1, base2
    for weight, group in sorted(items, key=lambda it: (-it[0], it[1][0].key)):
        if t1 <= t2:
            h1.extend(group)
            t1 += weight
        else:
            h2.extend(group)
            t2 += weight
    return h1, h2, t1, t2


def partition(exes, weights, prefixes):
    """Return (serial, half1, half2, lib_in_half1, totals). Lists hold Exe objects."""
    lib = [e for e in exes if e.kind == 'lib']
    others = [e for e in exes if e.kind != 'lib']
    for e in others:
        classify(e)
    means = class_means(others, weights)
    serial = [e for e in others if e.cls == 'a']
    b_exes = [e for e in others if e.cls == 'b']
    shared = [e for e in b_exes if e.shared]
    free = [e for e in b_exes if not e.shared]
    items = [(weight_of(e, weights, means), [e]) for e in free]
    if shared:
        items.append((sum(weight_of(e, weights, means) for e in shared), sorted(shared, key=lambda x: x.key)))
    lib_nonpg = weights.get('lib:nonpg', 0.0) if lib else 0.0
    lib_pg = weights.get('lib:pg', 0.0) if lib else 0.0
    h1, h2, t1, t2 = balance(items, lib_nonpg, 0.0)
    ts = lib_pg + sum(weight_of(e, weights, means) for e in serial)
    return serial, h1, h2, bool(lib), {'serial': ts, 'parallel_1': t1, 'parallel_2': t2}, means


def write_lists(out_dir, serial, h1, h2, has_lib):
    out_dir.mkdir(parents=True, exist_ok=True)
    spec = {'serial': serial, 'parallel_1': h1, 'parallel_2': h2}
    for name, exes in spec.items():
        lines = [e.selector for e in sorted(exes, key=lambda x: x.key)]
        if has_lib and name in ('serial', 'parallel_1'):
            lines.insert(0, '--lib')
        (out_dir / (name + '.txt')).write_text(''.join(l + '\n' for l in lines))


def verify_written(out_dir, exes):
    """Re-read the three list files; assert disjoint and complete. Fail loudly."""
    expected = {e.selector for e in exes if e.kind != 'lib'}
    got = {}
    for name in ('serial', 'parallel_1', 'parallel_2'):
        lines = [l for l in (out_dir / (name + '.txt')).read_text().splitlines() if l]
        non_lib = [l for l in lines if l != '--lib']
        if len(non_lib) != len(set(non_lib)):
            raise PartitionError('%s.txt lists a target twice' % name)
        got[name] = (set(non_lib), '--lib' in lines)
    s, p1, p2 = (got[n][0] for n in ('serial', 'parallel_1', 'parallel_2'))
    overlap = (s & p1) | (s & p2) | (p1 & p2)
    if overlap:
        raise PartitionError('shards overlap: %s' % sorted(overlap))
    union = s | p1 | p2
    if union != expected:
        raise PartitionError('union is not every executable: missing=%s extra=%s'
                             % (sorted(expected - union), sorted(union - expected)))
    has_lib = any(e.kind == 'lib' for e in exes)
    if has_lib != (got['serial'][1] and got['parallel_1'][1]) or got['parallel_2'][1]:
        raise PartitionError('--lib must appear in serial.txt and parallel_1.txt only (and only when the lib was built)')


def run(args):
    lines = sys.stdin if args.build_json == '-' else Path(args.build_json).read_text().splitlines()
    exes = parse_build_json(lines)
    repo = Path(args.repo_root)
    prefixes = load_prefixes(args.lib_pg_prefixes)
    has_lib = any(e.kind == 'lib' for e in exes)
    if has_lib:
        if not prefixes:
            raise PartitionError('lib_pg_prefixes is empty: the whole lib would run in the serial shard unfiltered')
        missing = uncovered_lib_pg_modules(repo / 'src', prefixes)
        if missing:
            raise PartitionError('lib modules read AI_MEMORY_TEST_POSTGRES_URL but no prefix in %s covers them: %s'
                                 % (args.lib_pg_prefixes, ', '.join(missing)))
    weights = load_weights(args.weights)
    serial, h1, h2, has_lib, totals, means = partition(exes, weights, prefixes)
    out_dir = Path(args.out_dir)
    write_lists(out_dir, serial, h1, h2, has_lib)
    (out_dir / 'lib_pg_filters.txt').write_text(''.join(p + '\n' for p in prefixes))
    verify_written(out_dir, exes)
    manifest = {
        'executables': len(exes),
        'counts': {'serial': len(serial) + (1 if has_lib else 0),
                   'parallel_1': len(h1) + (1 if has_lib else 0), 'parallel_2': len(h2)},
        'class_mean_seconds': means,
        'estimate_seconds': {
            'serial_threads_1': round(totals['serial'], 1),
            'parallel_1_serial_work': round(totals['parallel_1'], 1),
            'parallel_2_serial_work': round(totals['parallel_2'], 1),
            'parallel_1_ideal_threads_3': round(totals['parallel_1'] / 3, 1),
            'parallel_2_ideal_threads_3': round(totals['parallel_2'] / 3, 1),
        },
        'targets': {e.key: {'class': e.cls, 'reasons': e.reasons, 'shared': e.shared}
                    for e in exes if e.kind != 'lib'},
    }
    (out_dir / 'manifest.json').write_text(json.dumps(manifest, indent=1, sort_keys=True) + '\n')
    print('[#6344] shards: serial=%d parallel_1=%d parallel_2=%d of %d executables; '
          'estimate serial=%.0fs parallel=%.0fs/%.0fs (ideal, threads 3)'
          % (manifest['counts']['serial'], manifest['counts']['parallel_1'], manifest['counts']['parallel_2'],
             len(exes), totals['serial'], totals['parallel_1'] / 3, totals['parallel_2'] / 3))
    return 0


def build_parser():
    here = Path(__file__).resolve().parent
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--build-json', default='-', help="cargo --message-format=json output file ('-' = stdin)")
    ap.add_argument('--repo-root', default='.', help='repository root (for src/ scanning)')
    ap.add_argument('--out-dir', required=True, help='directory for the list files and manifest')
    ap.add_argument('--weights', default=str(here / 'test_binary_weights.json'))
    ap.add_argument('--lib-pg-prefixes', default=str(here / 'lib_pg_prefixes.txt'))
    return ap


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return run(args)
    except PartitionError as exc:
        print('::error::[#6344 shard] %s' % exc, file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
