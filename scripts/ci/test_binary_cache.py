#!/usr/bin/env python3
"""Per-test-binary result cache for the sharded enterprise-fed suite (#6384).

Stacked on scripts/ci/partition_test_binaries.py (#6344). Two sub-commands:

``plan``    After the partitioner has written serial.txt / parallel_1.txt /
            parallel_2.txt, compute a content key for every compiled test
            executable and drop from the shard lists every binary whose key
            equals the key of a prior GREEN run on the same base ref. Writes
            cache_plan.json and skip.txt next to the lists; the original lists
            are kept as ``<name>.txt.full``.
``record``  After a FULLY green test step (exit code 0) of a run whose policy
            allows recording (a push to ``release/**``, which never skips),
            write the plan's keys with result ``pass`` into the manifest.

The key (see ``build_key``) is sha256 over: the sorted (repo-relative path,
sha256) of every file in the executable's own cargo dep-info ``<exe>.d``; the
same for the SHARED closure (dep-info of every local lib / bin / build-script
unit, because an integration test links the lib and may run the bin, and a
dep-info for a test target lists only that target's own sources); Cargo.lock;
the ``rustc -Vv`` text; the feature/profile string; the behaviour-affecting
environment; the Postgres server identity (``SELECT version()`` and the
age / vector extension versions, or ``none`` without a test database URL);
and a digest of every file in the repo a test could read at run time that
rustc never saw (everything but build/VCS dirs and the ``.rs`` files under
src/ and tests/ that some dep-info of THIS build names; a ``.rs`` file no
dep-info names, such as a cfg-off module or an orphan, stays in). A binary
whose own sources look like a tree scanner (read_dir, walkdir, glob, a
"tests" path; integration test targets only) is keyed on the whole tree
including those ``.rs`` files, so a source-scanning test is never skipped
because some OTHER file changed.

Safety rules (enforced here, not only documented):

1. Consulted only when CI_TEST_BINARY_CACHE=1. Lookup additionally needs
   CI_TEST_BINARY_CACHE_LOOKUP=1 (r1 M5), which ci.yml sets for pull_request
   only, and this script grants on pull_request only: two independent locks,
   so a push to ``release/**`` can never skip a binary.
2. Who reads and who writes (decision of #6384 r2, review r1 M2; the
   fail-closed direction, so it needed no vote):
   * ``pull_request``: LOOK UP ONLY. A pull_request run
     never writes the manifest: its test code is unmerged and runs as the
     runner user, who can write the shared manifest directory.
   * ``push`` to ``release/**``: the seeding run. Lookup OFF (every binary
     runs), record ON after a fully green step.
   * Anything else (``chain/**`` pushes included): no lookup, no record.
   No policy both looks up and records, so a recorded ``pass`` always comes
   from a run that executed that binary.
3. A binary whose key cannot be computed (missing or unparsable .d, unreadable
   input) always runs. Any internal error leaves the full lists untouched.
4. A manifest or entry older than 7 days, from a different tier or base ref, or
   with a timestamp in the future is ignored.
5. Every hit prints the prior run_id, sha and recorded time.
6. ``record`` refuses unless the step exit code is exactly 0.

Fail direction: every doubt means "run the binary". Storage is a per-runner
directory; writes are atomic (temp file + rename) under an advisory lock.

Python 3.9+, standard library only.
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import partition_test_binaries as ptb  # noqa: E402

ISSUE = '#6384'
SCHEMA = 1
MAX_AGE_SECONDS = 7 * 24 * 3600
CLOCK_SKEW_SECONDS = 300
SHARD_LISTS = ('serial', 'parallel_1', 'parallel_2')
# Environment that changes what a test does (r1 H2). A self-hosted runner
# inherits its service environment, so EVERY variable of these families is in
# the key, not a hand-picked list: exact names, then name prefixes.
ENV_EXACT_KEYS = ('CI', 'RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTDOCFLAGS', 'RUST_MIN_STACK',
                  'RUST_BACKTRACE', 'RUST_LOG', 'TZ')
ENV_PREFIXES = ('AI_MEMORY_', 'RUST_TEST_', 'CARGO_PROFILE_', 'CARGO_BUILD_', 'PROPTEST_')
# A name that looks like it carries a credential or a per-job address counts
# by PRESENCE only (unset / empty / set). Its value is never hashed: a URL is a
# per-job ephemeral database and would make every key unique, and a secret
# must never reach a file, even hashed.
ENV_SECRET_NAME_RE = re.compile(r'URL|PASSWORD|PASSPHRASE|SECRET|TOKEN|KEY|CRED|DSN')
REGISTRY_MARKERS = ('/registry/src/', '/registry/cache/', '/git/checkouts/')


class CacheError(Exception):
    """Key or manifest cannot be trusted; the caller degrades to a full run."""


# ---------------------------------------------------------------- hashing ---

def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    h = hashlib.sha256()
    try:
        with open(path, 'rb') as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b''):
                h.update(chunk)
    except OSError as exc:
        raise CacheError('cannot read %s: %s' % (path, exc))
    return h.hexdigest()


# --------------------------------------------------------------- dep-info ---

def _split_deps(text):
    """Split the prerequisite part of a Makefile rule; ``\\ `` escapes a space."""
    out, cur, i = [], [], 0
    while i < len(text):
        ch = text[i]
        if ch == '\\' and i + 1 < len(text):
            nxt = text[i + 1]
            if nxt in ' \\#:':
                cur.append(nxt)
                i += 2
                continue
            if nxt == '\n':
                i += 2
                if cur:
                    out.append(''.join(cur))
                    cur = []
                continue
        if ch in ' \t\n':
            if cur:
                out.append(''.join(cur))
                cur = []
        else:
            cur.append(ch)
        i += 1
    if cur:
        out.append(''.join(cur))
    return out


def parse_depinfo(text):
    """Return (deps, env_deps) from a rustc dep-info file.

    deps is the sorted unique prerequisite list of the first rule;
    env_deps the sorted ``# env-dep:`` lines. Raises CacheError when no rule
    is found (an empty or unparsable file must never produce a key).
    """
    env_deps, rule_lines, in_rule = [], [], False
    for raw in text.splitlines(keepends=True):
        stripped = raw.strip()
        if stripped.startswith('# env-dep:'):
            env_deps.append(stripped)
            continue
        if stripped.startswith('#'):
            continue
        if not in_rule:
            if not stripped:
                continue
            in_rule = True
            rule_lines.append(raw)
            if not raw.rstrip('\r\n').endswith('\\'):
                break
        else:
            rule_lines.append(raw)
            if not raw.rstrip('\r\n').endswith('\\'):
                break
    if not rule_lines:
        raise CacheError('dep-info has no rule')
    rule = ''.join(rule_lines)
    # Split target from prerequisites at the first unescaped ": " / ":\n".
    m = re.search(r'(?<!\\):(?:\s|$)', rule)
    if not m:
        raise CacheError('dep-info rule has no target separator')
    deps = sorted(set(_split_deps(rule[m.end():])))
    return deps, sorted(set(env_deps))


def _is_registry(path):
    norm = str(path).replace('\\', '/')
    return any(mk in norm for mk in REGISTRY_MARKERS)


def digest_depinfo(depfile, repo_root):
    """List of ``(label, sha256)`` for every file a .d file names.

    Registry / git-checkout files are covered by Cargo.lock and skipped. A
    file inside the repo is labelled by its repo-relative path; a file outside
    it by ``ext:<basename>`` (never the absolute path: the runner work dir
    differs between hosts). Any missing file raises CacheError.
    """
    try:
        text = Path(depfile).read_text(errors='replace')
    except OSError as exc:
        raise CacheError('cannot read dep-info %s: %s' % (depfile, exc))
    deps, env_deps = parse_depinfo(text)
    root = Path(repo_root).resolve()
    out = []
    for d in deps:
        p = Path(d)
        if not p.is_absolute():
            p = root / p
        if _is_registry(p):
            continue
        try:
            rp = p.resolve()
        except OSError as exc:
            raise CacheError('cannot resolve %s: %s' % (d, exc))
        try:
            label = str(rp.relative_to(root))
        except ValueError:
            label = 'ext:' + rp.name
        if not rp.is_file():
            raise CacheError('dep-info names a missing file: %s' % d)
        out.append((label, sha256_file(rp)))
    # env!("CARGO_MANIFEST_DIR") and friends embed the checkout path, which
    # differs per runner work dir: normalise it so equal trees give equal keys.
    root_s = str(root)
    out.extend(('env-dep', sha256_bytes(e.replace(root_s, '<ROOT>').encode())) for e in env_deps)
    return sorted(set(out))


RUNTIME_SKIP_DIRS = {'.git', 'target', '.local-runs', '.codegraph', 'node_modules'}
# Compiled Rust sources whose changes dep-info already tracks per binary.
COMPILED_RS_ROOTS = ('src', 'tests')
# A binary whose own sources look like they read the tree at run time (a source
# scanner) is keyed on the WHOLE tree, .rs files included.
TREE_SENSITIVE_RE = re.compile(r'read_dir|walkdir|WalkDir|\bglob\b|"tests"|tests/|include_dir')


def digest_runtime_tree(root, include_compiled_rs, compiled_labels=None):
    """sha256 pairs of every file a test could read at run time.

    Everything under the repo except build/VCS dirs. A ``.rs`` file under src/
    or tests/ is skipped only when ``include_compiled_rs`` is false AND its
    repo-relative path is in ``compiled_labels`` (the union of every dep-info
    of this build, so a per-binary key already covers it). A ``.rs`` file no
    dep-info names (a cfg-off module, an orphan file) stays in: the lib's own
    tests scan src/ at run time (r1 H1). ``compiled_labels=None`` means "no
    dep-info known", so every ``.rs`` file stays in.
    """
    root = Path(root)
    compiled = frozenset(compiled_labels or ())
    out = []
    for dirpath, dirnames, filenames in os.walk(str(root)):
        rel_dir = Path(dirpath).relative_to(root)
        if rel_dir == Path('.'):
            dirnames[:] = sorted(d for d in dirnames if d not in RUNTIME_SKIP_DIRS)
        else:
            dirnames[:] = sorted(d for d in dirnames if d != '.git')
        for name in sorted(filenames):
            p = Path(dirpath) / name
            rel = p.relative_to(root)
            if (not include_compiled_rs and p.suffix == '.rs' and rel.parts[0] in COMPILED_RS_ROOTS
                    and str(rel) in compiled):
                continue
            if p.is_symlink() and not p.exists():
                continue
            out.append(('rt:' + str(rel), sha256_file(p)))
    return out


def tree_sensitive(depinfo_path, repo_root):
    """True when any own source of the binary looks like a tree scanner."""
    deps, _ = parse_depinfo(Path(depinfo_path).read_text(errors='replace'))
    root = Path(repo_root).resolve()
    for d in deps:
        p = Path(d)
        p = p if p.is_absolute() else root / p
        if _is_registry(p) or not p.is_file():
            continue
        try:
            if TREE_SENSITIVE_RE.search(p.read_text(errors='replace')):
                return True
        except OSError:
            return True
    return False


# ------------------------------------------------------------------- key ----

def env_name_in_key(name):
    return name in ENV_EXACT_KEYS or name.startswith(ENV_PREFIXES)


def env_fingerprint(env):
    """Stable string of the behaviour-affecting environment (r1 H2).

    One line per present variable of the families above, sorted by name. A
    plain setting contributes the sha256 of its value; a secret-like name
    (``ENV_SECRET_NAME_RE``) contributes only ``<empty>`` or ``<set>``. No raw
    value is ever part of the string.
    """
    parts = []
    for name in sorted(k for k in env if env_name_in_key(k)):
        val = env.get(name) or ''
        if ENV_SECRET_NAME_RE.search(name):
            parts.append('%s=%s' % (name, '<set>' if val else '<empty>'))
        else:
            parts.append('%s=sha256:%s' % (name, sha256_bytes(val.encode('utf-8', 'surrogateescape'))))
    return '\n'.join(parts)


PG_URL_ENV = 'AI_MEMORY_TEST_POSTGRES_URL'
PG_TIMEOUT_SECONDS = 30
PG_FINGERPRINT_SQL = (
    'SELECT version()',
    "SELECT name || ' ' || coalesce(default_version, '-') || ' ' || coalesce(installed_version, '-') "
    "FROM pg_available_extensions WHERE name IN ('age', 'vector') ORDER BY 1",
)


def pg_fingerprint(env, psql='psql', timeout=PG_TIMEOUT_SECONDS):
    """Identity of the Postgres server the tests talk to (r1 M1).

    ``none`` when no test database URL is set. Otherwise ``SELECT version()``
    plus the default and installed versions of the age and vector extensions,
    read through ``psql``. Any failure, timeout or empty answer raises
    CacheError, so an unknown server never yields a hit. The URL is passed to
    psql only; it is never part of the returned text.
    """
    url = env.get(PG_URL_ENV) or ''
    if not url:
        return 'none'
    cmd = [psql, '-X', '-A', '-t', '-q', '-v', 'ON_ERROR_STOP=1', '-d', url]
    for sql in PG_FINGERPRINT_SQL:
        cmd += ['-c', sql]
    try:
        res = subprocess.run(cmd, env=dict(env), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             stdin=subprocess.DEVNULL, timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise CacheError('cannot read the Postgres server fingerprint: %s' % type(exc).__name__)
    text = res.stdout.decode('utf-8', 'replace').strip()
    if res.returncode != 0 or not text:
        raise CacheError('cannot read the Postgres server fingerprint (psql exit %d)' % res.returncode)
    return text.replace(url, '<URL>')


def build_key(own_files, shared_files, lock_sha, rustc_vv, profile, env_fp, runtime_files=(), server_fp='none'):
    """Pure key function: every input is a plain value. Returns a hex digest."""
    h = hashlib.sha256()

    def feed(tag, value):
        data = value.encode() if isinstance(value, str) else value
        h.update(('%s:%d\n' % (tag, len(data))).encode())
        h.update(data)
        h.update(b'\n')

    feed('schema', str(SCHEMA))
    feed('lock', lock_sha)
    feed('rustc', rustc_vv)
    feed('profile', profile)
    feed('env', env_fp)
    feed('pg', server_fp)
    for tag, files in (('own', own_files), ('shared', shared_files), ('runtime', runtime_files)):
        for label, digest in sorted(set(files)):
            feed(tag, '%s\t%s' % (label, digest))
    return h.hexdigest()


# ------------------------------------------------------------ build json ----

def _read_lines(path):
    if path == '-':
        return sys.stdin.read().splitlines()
    return Path(path).read_text().splitlines()


def shared_depinfo_files(lines):
    """Dep-info paths of every local non-test unit and every test-profile lib/bin.

    Local = path source (not registry/git). Build scripts are included. Every
    candidate that exists on disk is returned; zero results means the shared
    closure is unknown (CacheError from the caller).
    """
    found = set()
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
        pid = msg.get('package_id') or ''
        if 'path+file://' not in pid:
            continue
        target = msg.get('target') or {}
        kinds = set(target.get('kind') or [])
        if not (kinds & {'lib', 'rlib', 'cdylib', 'staticlib', 'dylib', 'bin', 'custom-build', 'proc-macro'}):
            continue
        name = (target.get('name') or '').replace('-', '_')
        paths = list(msg.get('filenames') or [])
        if msg.get('executable'):
            paths.append(msg['executable'])
        for f in paths:
            p = Path(f)
            stem = p.stem if p.suffix in ('.rlib', '.rmeta', '.so', '.dylib', '.a', '.exe') else p.name
            cands = {p.parent / (stem + '.d')}
            if stem.startswith('lib'):
                cands.add(p.parent / (stem[3:] + '.d'))
            if p.parent.name != 'deps' and name:
                cands.update(sorted((p.parent / 'deps').glob(name + '-*.d')))
            found.update(c for c in cands if c.is_file())
    return sorted(found)


def exe_depinfo_path(executable):
    p = Path(str(executable) + '.d')
    if p.is_file():
        return p
    q = Path(executable).with_suffix('.d')
    if q.is_file():
        return q
    return None


def compute_keys(exes, build_lines, repo_root, rustc_vv, profile, env, runtime=True, server_fp='none'):
    """Return ({exe.key: hex or None}, {exe.key: reason}). Never raises per exe."""
    keys, why = {}, {}
    try:
        lock_sha = sha256_file(Path(repo_root) / 'Cargo.lock')
        shared = []
        sfiles = shared_depinfo_files(build_lines)
        if not sfiles:
            raise CacheError('no dep-info found for the local lib/bin/build-script units')
        for sf in sfiles:
            shared.extend(digest_depinfo(sf, repo_root))
    except CacheError as exc:
        for e in exes:
            keys[e.key], why[e.key] = None, 'shared inputs unavailable: %s' % exc
        return keys, why
    # Own dep-info per binary first: the union of every dep-info label decides
    # which .rs files the run-time tree may leave out (r1 H1).
    own_by_exe = {}
    for e in exes:
        try:
            dep = exe_depinfo_path(e.executable)
            if dep is None:
                raise CacheError('no .d file next to %s' % e.executable)
            own = digest_depinfo(dep, repo_root)
            if not own:
                raise CacheError('empty dep-info for %s' % e.key)
            own_by_exe[e.key] = (dep, own)
        except CacheError as exc:
            keys[e.key], why[e.key] = None, str(exc)
    compiled = {label for label, _ in shared}
    for _dep, own in own_by_exe.values():
        compiled.update(label for label, _ in own)
    try:
        rt_base = digest_runtime_tree(repo_root, False, compiled) if runtime else []
        rt_full = digest_runtime_tree(repo_root, True) if runtime else []
    except CacheError as exc:
        for e in exes:
            keys[e.key], why[e.key] = None, 'shared inputs unavailable: %s' % exc
        return keys, why
    env_fp = env_fingerprint(env)
    for e in exes:
        if e.key not in own_by_exe:
            continue
        dep, own = own_by_exe[e.key]
        try:
            rt = rt_full if (runtime and e.kind not in ('lib', 'bin') and tree_sensitive(dep, repo_root)) else rt_base
            keys[e.key] = build_key(own, shared, lock_sha, rustc_vv, profile, env_fp, rt, server_fp)
        except CacheError as exc:
            keys[e.key], why[e.key] = None, str(exc)
    return keys, why


# --------------------------------------------------------------- policy -----

def cache_policy(env, event, ref):
    """(lookup, record, reason). Safety rules 1 and 2 (see the module docstring)."""
    if env.get('CI_TEST_BINARY_CACHE') != '1':
        return False, False, 'CI_TEST_BINARY_CACHE is not 1'
    if event == 'pull_request':
        if env.get('CI_TEST_BINARY_CACHE_LOOKUP') != '1':
            return False, False, 'pull_request but CI_TEST_BINARY_CACHE_LOOKUP is not 1'
        return True, False, 'pull_request: lookup only, never records'
    if event == 'push':
        if ref.startswith('refs/heads/release/') or ref.startswith('release/'):
            return False, True, 'push to release/**: full run, results recorded as the seed'
        return False, False, 'push to %s is not a release branch' % (ref or '<unknown>')
    return False, False, 'event %r is not pull_request or push to release/**' % event


def cache_allowed(env, event, ref):
    """(lookup allowed, reason); kept for callers that only need the lookup bit."""
    lookup, _record, reason = cache_policy(env, event, ref)
    return lookup, reason


def safe_name(text):
    return re.sub(r'[^A-Za-z0-9_.-]', '_', text) or '_'


def manifest_path(manifest_dir, node, tier, base):
    return Path(manifest_dir) / ('test-manifest-%s-%s-%s.json' % (safe_name(node), safe_name(tier), safe_name(base)))


def load_manifest(path, tier, base, now):
    """Return valid prior entries ({} when absent, foreign, stale or corrupt)."""
    try:
        data = json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return {}, 'no usable prior manifest'
    if not isinstance(data, dict) or data.get('schema') != SCHEMA:
        return {}, 'manifest schema mismatch'
    if data.get('tier') != tier or data.get('base') != base:
        return {}, 'manifest is for tier=%r base=%r' % (data.get('tier'), data.get('base'))
    entries = data.get('entries')
    if not isinstance(entries, dict):
        return {}, 'manifest has no entries'
    valid = {}
    for name, ent in entries.items():
        if not isinstance(ent, dict):
            continue
        rec = ent.get('recorded_at')
        if not isinstance(rec, (int, float)) or isinstance(rec, bool):
            continue
        age = now - rec
        if age > MAX_AGE_SECONDS or age < -CLOCK_SKEW_SECONDS:
            continue
        if ent.get('base') != base or not isinstance(ent.get('key'), str):
            continue
        valid[name] = ent
    return valid, 'ok'


def decide(keys, prior):
    """Names to skip: key equal AND prior result pass (age/base already vetted)."""
    skip = {}
    for name, key in sorted(keys.items()):
        ent = prior.get(name)
        if key is not None and ent and ent.get('key') == key and ent.get('result') == 'pass':
            skip[name] = ent
    return skip


def selector_name(selector, lib_name):
    """Map a list line (``--lib`` / ``--test x``) to its exe key."""
    parts = selector.split()
    if parts == ['--lib']:
        return lib_name
    if len(parts) == 2 and parts[0].startswith('--'):
        return '%s:%s' % (parts[0][2:], parts[1])
    raise CacheError('unrecognised shard line %r' % selector)


def rewrite_lists(shard_dir, skip_names, lib_name):
    """Drop skipped selectors from the three lists. Returns (new_text, removed)."""
    new, removed = {}, {}
    for n in SHARD_LISTS:
        lines = [l for l in (Path(shard_dir) / (n + '.txt')).read_text().splitlines() if l]
        keep, drop = [], []
        for l in lines:
            (drop if selector_name(l, lib_name) in skip_names else keep).append(l)
        new[n], removed[n] = keep, drop
    return new, removed


def atomic_write(path, text):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name('.%s.%d.tmp' % (path.name, os.getpid()))
    tmp.write_text(text)
    os.replace(str(tmp), str(path))


# ------------------------------------------------------------------ plan ----

def run_plan(args, env=None, now=None):
    env = dict(os.environ if env is None else env)
    now = time.time() if now is None else now
    sd = Path(args.shard_dir)
    lookup, record, reason = cache_policy(env, args.event, args.ref)
    plan = {'schema': SCHEMA, 'enabled': False, 'lookup': False, 'record': False, 'reason': reason,
            'tier': args.tier, 'base': args.base_ref, 'node': args.node, 'keys': {}, 'skipped': {}}
    if not (lookup or record):
        atomic_write(sd / 'cache_plan.json', json.dumps(plan, indent=1, sort_keys=True) + '\n')
        print('::notice::[%s] test-binary cache off (%s): running every binary' % (ISSUE, reason))
        return 0
    try:
        if lookup and record:
            raise CacheError('policy both looks up and records (refused)')
        build_lines = _read_lines(args.build_json)
        exes = ptb.parse_build_json(build_lines)
        rustc_vv = Path(args.rustc_vv).read_text()
        if not rustc_vv.strip():
            raise CacheError('rustc -Vv file is empty')
        server_fp = pg_fingerprint(env, psql=args.psql)
        keys, why = compute_keys(exes, build_lines, args.repo_root, rustc_vv, args.profile, env,
                                 runtime=not args.no_runtime_tree, server_fp=server_fp)
        mpath = manifest_path(args.manifest_dir, args.node, args.tier, args.base_ref)
        if lookup:
            prior, prior_note = load_manifest(mpath, args.tier, args.base_ref, now)
            skip = decide(keys, prior)
        else:
            prior, prior_note, skip = {}, 'lookup off (record only)', {}
        lib_name = next((e.key for e in exes if e.kind == 'lib'), 'lib:')
        new_lists, removed = rewrite_lists(sd, set(skip), lib_name)
        # Invariant: every skipped binary was removed from some list, and
        # nothing else was.
        gone = {selector_name(l, lib_name) for v in removed.values() for l in v}
        if gone != set(skip):
            raise CacheError('skip set and removed shard lines disagree')
    except (CacheError, ptb.PartitionError, OSError, ValueError) as exc:
        print('::warning::[%s] test-binary cache disabled for this run (%s): running every binary' % (ISSUE, exc))
        plan['reason'] = 'error: %s' % exc
        try:
            atomic_write(sd / 'cache_plan.json', json.dumps(plan, indent=1, sort_keys=True) + '\n')
        except OSError:
            pass
        return 0
    # Everything computed; now touch the files.
    for n in SHARD_LISTS:
        src = sd / (n + '.txt')
        atomic_write(sd / (n + '.txt.full'), src.read_text())
        atomic_write(src, ''.join(l + '\n' for l in new_lists[n]))
    atomic_write(sd / 'skip.txt', ''.join(sorted(n + '\n' for n in skip)))
    plan.update({
        'enabled': True, 'lookup': lookup, 'record': record, 'reason': reason, 'prior_note': prior_note, 'run_id': args.run_id, 'sha': args.sha,
        'keys': keys, 'key_errors': why,
        'skipped': {n: {k: v for k, v in e.items()} for n, e in skip.items()},
    })
    atomic_write(sd / 'cache_plan.json', json.dumps(plan, indent=1, sort_keys=True) + '\n')
    n_total = len(exes)
    n_skip = len(skip)
    n_nokey = sum(1 for k in keys.values() if k is None)
    print('::group::[%s] test-binary cache hits (audit trail)' % ISSUE)
    for n, e in sorted(skip.items()):
        print('hit %s key=%s prior_run_id=%s prior_sha=%s recorded_at=%s base=%s'
              % (n, e['key'][:16], e.get('run_id'), e.get('sha'),
                 time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(e['recorded_at'])), e.get('base')))
    for n, r in sorted(why.items()):
        print('nokey %s: %s' % (n, r))
    print('::endgroup::')
    print('::notice::[%s] skipped %d of %d binaries (cache hits), running %d (%d without a computable key; prior manifest: %s)'
          % (ISSUE, n_skip, n_total, n_total - n_skip, n_nokey, prior_note))
    return 0


# ---------------------------------------------------------------- record ----

class _Lock:
    def __init__(self, path):
        self.path = path
        self.fh = None

    def __enter__(self):
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.fh = open(self.path, 'a')
        try:
            import fcntl
            fcntl.flock(self.fh, fcntl.LOCK_EX)
        except (ImportError, OSError):
            pass
        return self

    def __exit__(self, *exc):
        self.fh.close()


def run_record(args, now=None):
    now = time.time() if now is None else now
    if args.rc != 0:
        print('::notice::[%s] test-binary cache not recorded: step exit code %s is not 0' % (ISSUE, args.rc))
        return 0
    try:
        plan = json.loads((Path(args.shard_dir) / 'cache_plan.json').read_text())
    except (OSError, ValueError) as exc:
        print('::notice::[%s] test-binary cache not recorded: no readable plan (%s)' % (ISSUE, exc))
        return 0
    if not plan.get('enabled'):
        print('::notice::[%s] test-binary cache not recorded: cache was off (%s)' % (ISSUE, plan.get('reason')))
        return 0
    if plan.get('record') is not True or plan.get('lookup') is not False or plan.get('skipped'):
        # Only a run that looked nothing up and skipped nothing may write
        # (r1 M2): a pull_request plan has record=false.
        print('::notice::[%s] test-binary cache not recorded: this run may not write the manifest (%s)'
              % (ISSUE, plan.get('reason')))
        return 0
    tier, base, node = plan['tier'], plan['base'], plan['node']
    mpath = manifest_path(args.manifest_dir, node, tier, base)
    with _Lock(str(mpath) + '.lock'):
        prior, _ = load_manifest(mpath, tier, base, now)
        entries = dict(prior)
        recorded = dropped = 0
        for name, key in sorted(plan['keys'].items()):
            if key is None:
                entries.pop(name, None)
                dropped += 1
            else:
                entries[name] = {'key': key, 'result': 'pass', 'run_id': args.run_id, 'sha': args.sha,
                                 'base': base, 'recorded_at': now}
                recorded += 1
        doc = {'schema': SCHEMA, 'tier': tier, 'base': base, 'node': node, 'updated_at': now,
               'updated_run_id': args.run_id, 'entries': entries}
        atomic_write(mpath, json.dumps(doc, indent=1, sort_keys=True) + '\n')
    print('::notice::[%s] test-binary cache recorded: %d pass, %d without key (%d entries in %s)'
          % (ISSUE, recorded, dropped, len(entries), mpath.name))
    return 0


# ------------------------------------------------------------------- cli ----

def build_parser():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    sub = ap.add_subparsers(dest='cmd', required=True)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument('--shard-dir', required=True)
    common.add_argument('--manifest-dir', required=True)
    common.add_argument('--run-id', default='')
    common.add_argument('--sha', default='')
    pl = sub.add_parser('plan', parents=[common])
    pl.add_argument('--build-json', required=True)
    pl.add_argument('--repo-root', default='.')
    pl.add_argument('--rustc-vv', required=True, help='file holding `rustc -Vv` output (written by the workflow)')
    pl.add_argument('--profile', default='', help='feature/profile string, e.g. "test sal-postgres"')
    pl.add_argument('--tier', required=True)
    pl.add_argument('--node', required=True)
    pl.add_argument('--base-ref', required=True)
    pl.add_argument('--event', required=True)
    pl.add_argument('--ref', default='')
    pl.add_argument('--psql', default='psql', help='psql used for the Postgres server fingerprint')
    pl.add_argument('--no-runtime-tree', action='store_true',
                    help='TESTS ONLY: skip the run-time file tree digest (never set by the workflow)')
    rc = sub.add_parser('record', parents=[common])
    rc.add_argument('--rc', type=int, required=True, help='exit code of the test step; must be 0')
    return ap


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.cmd == 'plan':
        return run_plan(args)
    return run_record(args)


if __name__ == '__main__':
    sys.exit(main())
