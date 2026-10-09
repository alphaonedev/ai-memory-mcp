#!/usr/bin/env python3
"""Per-test-binary result cache for the sharded enterprise-fed suite (#6384).

Stacked on scripts/ci/partition_test_binaries.py (#6344). Three sub-commands:

``plan``    After the partitioner has written serial.txt / parallel_1.txt /
            parallel_2.txt, compute a content key for every compiled test
            executable and drop from the shard lists every binary whose key
            equals the key of a prior GREEN run on the same base ref. Writes
            cache_plan.json and skip.txt next to the lists; the original lists
            are kept as ``<name>.txt.full``.
``restore`` Put the ``.txt.full`` lists back and disable the plan; the
            workflow runs it when ``plan`` fails or overruns its deadline.
``record``  After a FULLY green test step (exit code 0) of a run whose policy
            allows recording (a push to ``release/**``, which never skips),
            write the plan's keys with result ``pass`` into the manifest.

The key (see ``build_key``) is sha256 over: the sorted (repo-relative path,
sha256) of every file in the executable's own cargo dep-info ``<exe>.d``; the
same for the SHARED closure (dep-info of every local lib / bin / build-script
unit, because an integration test links the lib and may run the bin, and a
dep-info for a test target lists only that target's own sources); the cfgs,
env and ``output`` file of every local build-script run; Cargo.lock;
the ``rustc -Vv`` and ``cargo -V`` texts; the feature/profile string; the
behaviour-affecting environment; the Postgres server identity (``SELECT
version()``, the age / vector extension versions and the max_connections,
server_version_num and shared_preload_libraries settings, or ``none``
without a test database URL);
and a digest of every file in the repo a test could read at run time that
rustc never saw. That digest leaves out build/VCS dirs and the ``.rs`` files
a build-independent rule marks compiled (r2 M1: an impact build compiles a
subset, and a key must not depend on which): src/ files the shared non-test
closure or the lib unittest's dep-info names, and tests/ files reachable from
a cargo test-target root (``static_test_labels``). An orphan or a cfg-off
module stays in. docs/ and *.md are in the key only of a binary whose OWN
sources name them (``docs`` or ``.md`` outside a ``//`` comment; r1 M4);
changelog.d/ only of a binary that can read it (``source_traits``: names
``changelog``, spawns a tool or a repo script, or walks the repo root; r2
M1). A binary whose own sources look like a tree scanner (read_dir, walkdir,
glob, a "tests" path; integration test targets only) is keyed on the whole
tree including those ``.rs`` files, so a source-scanning test is never
skipped because some OTHER file changed. A docs-only pull request never
reaches this script (``__SKIP__`` in ci.yml), and a src/ edit changes the
shared closure, so the hits come from pull requests that touch only tests/
and changelog.d/.

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
3. ``plan`` has a hard deadline (``--timeout-seconds``, 120 by default) and
   never opens a FIFO, socket or device in the tree; on expiry nothing is
   skipped (r1 M3). A binary whose key cannot be computed (missing or unparsable .d, unreadable
   input) always runs. Any internal error leaves the full lists untouched.
4. A manifest or entry older than 7 days, from a different tier or base ref, or
   with a timestamp in the future is ignored.
5. Every hit prints the prior run_id, sha and recorded time.
6. ``record`` refuses unless the step exit code is exactly 0.

Fail direction: every doubt means "run the binary". Storage is a per-runner
directory; writes are atomic (temp file + rename) under an advisory lock
that fails closed (no lock, no record), and each record sweeps files older
than 7 days (r1 L4).

Python 3.9+, standard library only.
"""
import argparse
import hashlib
import json
import os
import re
import signal
import stat
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


# Documentation a test binary only reads when its code names it (r1 M4). The
# changelog fragments are their own class (r2 M1): every pull request adds one.
CHANGELOG_ROOT = 'changelog.d'
DOC_ROOTS = (CHANGELOG_ROOT, 'docs')
DOC_SUFFIXES = ('.md',)
# A binary whose code (``//`` line comments ignored) matches this is keyed on
# docs/ and *.md.
DOC_READER_RE = re.compile(r'\bdocs\b|\.md\b', re.I)
# ... and on changelog.d/ when it names it, spawns a tool that may read it,
# names an existing repo script, or (integration tests) walks the repo root.
CHANGELOG_READER_RE = re.compile(r'changelog', re.I)
TOOL_SPAWN_RE = re.compile(r'Command::new\(\s*"(?:bash|sh|zsh|dash|git|find|grep|rg|python|python3|perl|xargs|env|make)"')
SCRIPT_PATH_RE = re.compile(r'"(?:\./)?(scripts/[\w./-]+\.(?:sh|py))"')
ENUM_RE = re.compile(r'\bread_dir\b|\bWalkDir\b|\bwalkdir\b|\bglob\b|\binclude_dir\b')
ROOT_EXPR_RE = re.compile(r'env!\(\s*"CARGO_MANIFEST_DIR"\s*\)|\bcurrent_dir\(\s*\)')
BARE_WALK_RE = re.compile(r'\b(?:read_dir|WalkDir::new|walkdir|glob)\(\s*"(?:\.|\./|\*[^"]*)?"')
_TAIL_RE = re.compile(r'\s*(?:\)|\?|\.(?:unwrap|expect|context|with_context|unwrap_or_else|to_path_buf|as_path'
                      r'|canonicalize|to_owned|clone)\s*\()')
_JOIN_LIT_RE = re.compile(r'\s*\.join\(\s*"([^"]*)"')
_CONCAT_LIT_RE = re.compile(r'\s*,\s*"([^"]*)"')
_BIND_RE = re.compile(r'\b(?:let\s+(?:mut\s+)?|const\s+|static\s+)(\w+)\s*(?::[^=]*)?=')
_WRAP_RE = re.compile(r'\s*(?:&?\s*(?:std::)?(?:path::)?(?:PathBuf::from|Path::new)\(\s*)*$')
_MOD_RE = re.compile(r'(?:#\[path\s*=\s*"([^"\n]+)"\]\s*)?(?:pub(?:\([^)]*\))?\s+)?mod\s+(\w+)\s*;')
_INCLUDE_RE = re.compile(r'\binclude(?:_str|_bytes)?!\(\s*"([^"\n]+)"')


def label_class(rel):
    """'changelog' (changelog.d/), 'docs' (docs/ or another *.md) or None."""
    rel = Path(rel)
    if not rel.parts:
        return None
    if rel.parts[0] == CHANGELOG_ROOT:
        return 'changelog'
    if rel.parts[0] in DOC_ROOTS or rel.suffix.lower() in DOC_SUFFIXES:
        return 'docs'
    return None


def is_doc_label(rel):
    """True for a repo-relative path under changelog.d/ or docs/, or a *.md file."""
    return label_class(rel) is not None


def digest_runtime_tree(root, include_compiled_rs, compiled_labels=None, include_docs=None):
    """sha256 pairs of every file a test could read at run time.

    Everything under the repo except build/VCS dirs. A ``.rs`` file under src/
    or tests/ is skipped only when ``include_compiled_rs`` is false AND its
    repo-relative path is in ``compiled_labels`` (the union of every dep-info
    of this build, so a per-binary key already covers it). A ``.rs`` file no
    dep-info names (a cfg-off module, an orphan file) stays in: the lib's own
    tests scan src/ at run time (r1 H1). ``compiled_labels=None`` means "no
    dep-info known", so every ``.rs`` file stays in.

    ``include_docs`` (default: same as ``include_compiled_rs``) keeps the
    documentation (``is_doc_label``) in; the base digest leaves it out (r1 M4).
    """
    if include_docs is None:
        include_docs = include_compiled_rs
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
            if not include_docs and is_doc_label(rel):
                continue
            out.append(('rt:' + str(rel), runtime_entry_digest(p)))
    return out


def _special_kind(mode):
    for test, kind in ((stat.S_ISFIFO, 'fifo'), (stat.S_ISSOCK, 'socket'), (stat.S_ISCHR, 'chardev'),
                       (stat.S_ISBLK, 'blockdev'), (stat.S_ISDIR, 'dir')):
        if test(mode):
            return kind
    return 'other'


def _hash_regular(path, follow):
    """sha256 of a regular file, or None when the path is not one.

    Opened with O_NONBLOCK (and O_NOFOLLOW unless ``follow``), then checked
    with fstat, so a FIFO or device swapped in after the lstat is never read
    (r1 M3).
    """
    flags = os.O_RDONLY | getattr(os, 'O_NONBLOCK', 0)
    if not follow:
        flags |= getattr(os, 'O_NOFOLLOW', 0)
    try:
        fd = os.open(str(path), flags)
    except OSError as exc:
        raise CacheError('cannot open %s: %s' % (path, exc))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        h = hashlib.sha256()
        with os.fdopen(fd, 'rb') as fh:
            fd = None
            for chunk in iter(lambda: fh.read(1 << 20), b''):
                h.update(chunk)
        return h.hexdigest()
    except OSError as exc:
        raise CacheError('cannot read %s: %s' % (path, exc))
    finally:
        if fd is not None:
            os.close(fd)


def runtime_entry_digest(path):
    """Digest string for one directory entry of the run-time tree (r1 M3).

    A regular file contributes the sha256 of its content. A FIFO, socket or
    device is never opened: it contributes ``special:<kind>``. A symlink to a
    regular file contributes the target's content (a test reading through the
    link sees that content); any other symlink contributes its target text.
    """
    try:
        st = os.lstat(str(path))
    except OSError as exc:
        raise CacheError('cannot stat %s: %s' % (path, exc))
    if stat.S_ISLNK(st.st_mode):
        try:
            target = os.readlink(str(path))
        except OSError as exc:
            raise CacheError('cannot read link %s: %s' % (path, exc))
        try:
            tst = os.stat(str(path))
        except OSError:
            return 'link-dangling:' + sha256_bytes(target.encode())
        if stat.S_ISREG(tst.st_mode):
            h = _hash_regular(path, follow=True)
            if h is not None:
                return h
        return 'link-special:%s:%s' % (_special_kind(tst.st_mode), sha256_bytes(target.encode()))
    if stat.S_ISREG(st.st_mode):
        h = _hash_regular(path, follow=False)
        if h is not None:
            return h
        return 'special:changed-during-walk'
    return 'special:' + _special_kind(st.st_mode)


def _code_lines(text):
    """``text`` with every line whose first non-blank characters are ``//`` blanked."""
    return '\n'.join('' if l.lstrip().startswith('//') else l for l in text.splitlines())


def _lit_ok(lit):
    """A path literal naming a subpath that is not changelog.d/."""
    s = lit.strip().lstrip('./')
    return bool(s) and not s.lower().startswith('changelog')


def _skip_tails(t, i):
    """Index after the call tails at ``i`` (``)``, ``?``, ``.unwrap()``, ``.expect("..")``)."""
    while True:
        m = _TAIL_RE.match(t, i)
        if not m:
            return i
        i, depth = m.end(), 1 if t[m.end() - 1] == '(' else 0
        while i < len(t) and depth:
            if t[i] == '"':
                j = i + 1
                while j < len(t) and t[j] != '"':
                    j += 2 if t[j] == '\\' else 1
                i = j
            else:
                depth += {'(': 1, ')': -1}.get(t[i], 0)
            i += 1


def _joined_at(t, i):
    m = _JOIN_LIT_RE.match(t, _skip_tails(t, i))
    return bool(m) and _lit_ok(m.group(1))


def _root_anchored(t, m):
    """True when the repo-root expression ``m`` only reaches a named subpath:
    ``concat!(root, "/x")``, ``root….join("x")``, or a ``let``/``const``/
    ``static`` binding of exactly that expression whose every later use is
    joined so (r2 M1). Anything else counts as a walk of the whole root."""
    head = t[:m.start()]
    if re.search(r'concat!\(\s*$', head):
        c = _CONCAT_LIT_RE.match(t, m.end())
        return bool(c) and _lit_ok(c.group(1))
    if _joined_at(t, m.end()):
        return True
    stmt = head[max(head.rfind(';'), head.rfind('{'), head.rfind('}')) + 1:]
    b = _BIND_RE.search(stmt)
    end = _skip_tails(t, m.end())
    # The binding must hold exactly the root (optionally wrapped in
    # Path::new / PathBuf::from), and the statement must end there.
    if not b or b.group(1) == '_' or not _WRAP_RE.match(stmt[b.end():]) or t[end:end + 1] != ';':
        return False
    uses = re.finditer(r'\b%s\b' % re.escape(b.group(1)), t[end:])
    return all(_joined_at(t, end + u.end()) for u in uses)


def source_traits(texts, kind, repo_root):
    """{'tree', 'docs', 'changelog'} for a binary with own sources ``texts``.

    * tree: an integration test whose code matches TREE_SENSITIVE_RE (the lib
      and bins never; their run-time walks stay inside src/, r1 H1).
    * changelog (r2 M1): the code names ``changelog``, spawns a shell, git or
      search tool, or names an existing repo script (either may read
      changelog.d/); or, for an integration test, it enumerates files
      (ENUM_RE) and holds a repo-root expression that is not joined to a named
      subpath (a walk from the root reaches changelog.d/).
    * docs: a changelog reader, or the code names docs/ or *.md (r1 M4).

    ``//`` line comments do not count except for ``tree``.
    """
    code = [_code_lines(x) for x in texts]
    joined = '\n'.join(code)
    test = kind not in ('lib', 'bin')
    root = Path(repo_root)
    changelog = bool(CHANGELOG_READER_RE.search(joined) or TOOL_SPAWN_RE.search(joined)
                     or any((root / m.group(1)).is_file() for m in SCRIPT_PATH_RE.finditer(joined)))
    if test and not changelog and ENUM_RE.search(joined):
        changelog = bool(BARE_WALK_RE.search(joined)) or any(
            not _root_anchored(c, m) for c in code for m in ROOT_EXPR_RE.finditer(c))
    return {'tree': test and bool(TREE_SENSITIVE_RE.search('\n'.join(texts))),
            'docs': changelog or bool(DOC_READER_RE.search(joined)), 'changelog': changelog}


def binary_traits(depinfo_path, repo_root, kind):
    """source_traits over the binary's own (non-registry) dep-info sources. An
    unreadable source makes every trait true (the conservative direction)."""
    deps, _ = parse_depinfo(Path(depinfo_path).read_text(errors='replace'))
    root = Path(repo_root).resolve()
    texts = []
    for d in deps:
        q = Path(d)
        q = q if q.is_absolute() else root / q
        if _is_registry(q) or not q.is_file():
            continue
        try:
            texts.append(q.read_text(errors='replace'))
        except OSError:
            return {'tree': kind not in ('lib', 'bin'), 'docs': True, 'changelog': True}
    return source_traits(texts, kind, repo_root)


def test_target_roots(repo_root):
    """Cargo's integration-test roots, independent of what a build compiled
    (r2 M1): tests/*.rs, tests/*/main.rs and each ``[[test]] path`` of Cargo.toml."""
    root = Path(repo_root)
    found = set(root.glob('tests/*.rs')) | set(root.glob('tests/*/main.rs'))
    try:
        manifest = (root / 'Cargo.toml').read_text(errors='replace')
    except OSError:
        manifest = ''
    for block in re.split(r'(?m)^\s*\[', manifest):
        m = re.search(r'(?m)^\s*path\s*=\s*"([^"]+)"', block) if block.startswith('[test]]') else None
        if m:
            found.add(root / m.group(1))
    return sorted(q for q in found if q.is_file())


def static_mod_closure(repo_root, *roots):
    """Every file reachable from ``roots`` through ``mod x;`` (``#[path]``
    honoured) and ``include!``-family literals, as paths under ``repo_root``.

    Both module layouts are tried and cfg is ignored, so it over-approximates;
    a file it misses stays in the run-time key, the safe direction.
    """
    seen, todo = set(), [Path(os.path.normpath(str(r))) for r in roots]
    while todo:
        q = todo.pop()
        if q in seen:
            continue
        try:
            if not q.is_file():
                continue
            text = _code_lines(q.read_text(errors='replace'))
        except OSError:
            continue
        seen.add(q)
        for m in _MOD_RE.finditer(text):
            if m.group(1):
                todo.append(q.parent / m.group(1))
            else:
                n = m.group(2)
                for base in (q.parent, q.with_suffix('')):
                    todo += [base / (n + '.rs'), base / n / 'mod.rs']
        todo += [q.parent / m.group(1) for m in _INCLUDE_RE.finditer(text)]
        todo = [Path(os.path.normpath(str(x))) for x in todo]
    return sorted(seen)


def static_test_labels(repo_root):
    """Repo-relative labels of the tests/**.rs files a cargo test target compiles."""
    root = Path(os.path.normpath(str(Path(repo_root).resolve())))
    out = set()
    for q in static_mod_closure(root, *[root / r.relative_to(Path(repo_root)) for r in test_target_roots(repo_root)]):
        try:
            rel = q.relative_to(root)
        except ValueError:
            continue
        if rel.parts and rel.parts[0] == 'tests' and q.suffix == '.rs':
            out.add(str(rel))
    return out


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
    # r2 L1: server settings that change test behaviour (pool limits,
    # preloaded libraries, the exact server build).
    "SELECT name || '=' || setting FROM pg_settings "
    "WHERE name IN ('max_connections', 'server_version_num', 'shared_preload_libraries') ORDER BY 1",
)
CARGO_TIMEOUT_SECONDS = 30


def cargo_version(path, env, cargo='cargo', timeout=CARGO_TIMEOUT_SECONDS):
    """The ``cargo -V`` text (r2 L1): read from ``path`` when one is given
    (the workflow writes it next to rustc-vv.txt), else asked of ``cargo``.
    An unreadable file, a failing or missing cargo, or an empty answer raises
    CacheError, so an unknown cargo never yields a hit."""
    if path:
        try:
            text = Path(path).read_text()
        except (OSError, UnicodeDecodeError) as exc:
            raise CacheError('cannot read the cargo version file: %s' % type(exc).__name__)
    else:
        try:
            res = subprocess.run([cargo, '-V'], env=dict(env), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                 stdin=subprocess.DEVNULL, timeout=timeout, check=False)
        except (OSError, subprocess.SubprocessError) as exc:
            raise CacheError('cannot run cargo -V: %s' % type(exc).__name__)
        if res.returncode != 0:
            raise CacheError('cargo -V failed (exit %d)' % res.returncode)
        text = res.stdout.decode('utf-8', 'replace')
    if not text.strip():
        raise CacheError('cargo version is empty')
    return text


def pg_fingerprint(env, psql='psql', timeout=PG_TIMEOUT_SECONDS):
    """Identity of the Postgres server the tests talk to (r1 M1).

    ``none`` when no test database URL is set. Otherwise ``SELECT version()``
    plus the default and installed versions of the age and vector extensions
    and the ``max_connections``, ``server_version_num`` and
    ``shared_preload_libraries`` settings (r2 L1), read through ``psql``. Any failure, timeout or empty answer raises
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


def build_key(own_files, shared_files, lock_sha, rustc_vv, profile, env_fp, runtime_files=(), server_fp='none',
              cargo_v=''):
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
    feed('cargo', cargo_v)
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
    """Dep-info paths of every local NON-TEST lib / bin / build-script unit.

    Local = path source (not registry/git). Build scripts are included. Only
    the exact dep-info next to a file this build reported counts (no glob over
    deps/, whose old ``<name>-<hash>.d`` files outlive their builds; r1 L2).
    Every candidate that exists on disk is returned; zero results means the shared
    closure is unknown (CacheError from the caller). A test-profile unit (the
    lib or bin unittest) is never shared (r2 M1): an integration test links the
    non-test lib and runs the non-test bin, the unittest has its own key, and
    an impact build (``--lib --test x``) does not build the bin unittest.
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
        if (msg.get('profile') or {}).get('test'):
            continue
        target = msg.get('target') or {}
        kinds = set(target.get('kind') or [])
        if not (kinds & {'lib', 'rlib', 'cdylib', 'staticlib', 'dylib', 'bin', 'custom-build', 'proc-macro'}):
            continue
        paths = list(msg.get('filenames') or [])
        if msg.get('executable'):
            paths.append(msg['executable'])
        for f in paths:
            p = Path(f)
            stem = p.stem if p.suffix in ('.rlib', '.rmeta', '.so', '.dylib', '.a', '.exe') else p.name
            cands = {p.parent / (stem + '.d')}
            if stem.startswith('lib'):
                cands.add(p.parent / (stem[3:] + '.d'))
            if 'custom-build' in kinds and '-' in p.parent.name:
                # <build>/<pkg>-<hash>/build_script_build-<hash>.d (r1 L1).
                cands.add(p.parent / ('build_script_build-%s.d' % p.parent.name.rsplit('-', 1)[1]))
            found.update(c for c in cands if c.is_file())
    return sorted(found)


def build_script_outputs(lines, repo_root):
    """Key pairs for every local build-script RUN (r1 L1).

    One pair per ``build-script-executed`` message of a path package: the
    sha256 of its cfgs, env, linked libs and paths, plus the content of the
    run's ``output`` file (``<out_dir>/../output``) when it exists. The
    checkout and the target profile dir are normalised so equal runs on two
    work dirs give equal pairs. A listed but unreadable ``output`` file raises
    CacheError (the shared inputs are then unknown and everything runs).
    """
    root_s = str(Path(repo_root).resolve())
    out = []
    for raw in lines:
        raw = raw.strip()
        if not raw.startswith('{'):
            continue
        try:
            msg = json.loads(raw)
        except ValueError:
            continue
        if msg.get('reason') != 'build-script-executed':
            continue
        pid = msg.get('package_id') or ''
        if 'path+file://' not in pid:
            continue
        out_dir = Path(msg.get('out_dir') or '')
        run_dir = out_dir.parent
        prof = str(run_dir.parent.parent) if len(run_dir.parts) > 2 else ''

        def norm(text):
            text = text.replace(prof, '<TARGET>') if prof else text
            return text.replace(root_s, '<ROOT>')
        meta = {k: msg.get(k) for k in ('cfgs', 'env', 'linked_libs', 'linked_paths')}
        label = 'build-run:%s:%s' % (pid.rsplit('#', 1)[-1], run_dir.name)
        out.append((label + ':meta', sha256_bytes(norm(json.dumps(meta, sort_keys=True)).encode())))
        output = run_dir / 'output'
        if output.exists():
            try:
                text = output.read_text(errors='replace')
            except OSError as exc:
                raise CacheError('cannot read %s: %s' % (output, exc))
            out.append((label + ':output', sha256_bytes(norm(text).encode())))
    return sorted(out)


def exe_depinfo_path(executable):
    p = Path(str(executable) + '.d')
    if p.is_file():
        return p
    q = Path(executable).with_suffix('.d')
    if q.is_file():
        return q
    return None


def compute_keys(exes, build_lines, repo_root, rustc_vv, profile, env, runtime=True, server_fp='none', cargo_v=''):
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
        shared.extend(build_script_outputs(build_lines, repo_root))
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
    # The .rs files the narrow run-time keys leave out (r1 H1, r2 M1). Only
    # facts that do not depend on which targets this build compiled: src/
    # files the shared non-test closure or the lib unittest's own dep-info
    # names (the lib is in every build), and tests/ files reachable from a
    # cargo test-target root. An orphan or a cfg-off module stays in every key.
    compiled = {label for label, _ in shared if label.startswith('src/')}
    for e in exes:
        if e.kind == 'lib' and e.key in own_by_exe:
            compiled.update(label for label, _ in own_by_exe[e.key][1] if label.startswith('src/'))
    try:
        compiled |= static_test_labels(repo_root)
        walk = digest_runtime_tree(repo_root, True) if runtime else []
    except (CacheError, OSError) as exc:
        for e in exes:
            keys[e.key], why[e.key] = None, 'shared inputs unavailable: %s' % exc
        return keys, why
    views = {}

    def view(full, docs, changelog):
        """The run-time pairs of one trait combination (memoised)."""
        sel = (full, docs or full, changelog)
        if sel not in views:
            out = []
            for label, digest in walk:
                rel = label[len('rt:'):]
                cls = label_class(rel)
                if (cls == 'changelog' and not sel[2]) or (cls == 'docs' and not sel[1]):
                    continue
                if not full and rel.endswith('.rs') and rel in compiled:
                    continue
                out.append((label, digest))
            views[sel] = out
        return views[sel]

    env_fp = env_fingerprint(env)
    for e in exes:
        if e.key not in own_by_exe:
            continue
        dep, own = own_by_exe[e.key]
        try:
            tr = binary_traits(dep, repo_root, e.kind) if runtime else {}
            rt = view(tr['tree'], tr['docs'], tr['changelog']) if runtime else []
            keys[e.key] = build_key(own, shared, lock_sha, rustc_vv, profile, env_fp, rt, server_fp, cargo_v)
        except (CacheError, OSError) as exc:
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


def manifest_path(manifest_dir, node, tier, base):
    """``test-manifest-<sha256(node NUL tier NUL base)[:32]>.json`` (r1 L5).

    A hash, not a character substitution, so ``release/v1`` and
    ``release_v1`` never share a file. The node, tier and base are stored in
    the manifest and re-checked on load.
    """
    digest = sha256_bytes(('%s\0%s\0%s' % (node, tier, base)).encode())[:32]
    return Path(manifest_dir) / ('test-manifest-%s.json' % digest)


MANIFEST_SUBDIR = Path('ai-memory-ci') / 'test-manifest'


def resolve_manifest_dir(arg, env, repo_root):
    """The manifest directory (r1 L5): ``--manifest-dir``, else
    $CI_TEST_MANIFEST_DIR, else $HOME/.cache/ai-memory-ci/test-manifest, else
    $RUNNER_TEMP/ai-memory-ci/test-manifest, else
    <repo>/.local-runs/ai-memory-ci/test-manifest."""
    for cand in (arg, env.get('CI_TEST_MANIFEST_DIR')):
        if cand:
            return Path(cand)
    if env.get('HOME'):
        return Path(env['HOME']) / '.cache' / MANIFEST_SUBDIR
    if env.get('RUNNER_TEMP'):
        return Path(env['RUNNER_TEMP']) / MANIFEST_SUBDIR
    return Path(repo_root) / '.local-runs' / MANIFEST_SUBDIR


def check_manifest_dir(manifest_dir, repo_root):
    """Refuse a manifest dir inside the checkout outside ``.local-runs/``: there
    it would change the run-time tree key and be wiped by a clean (r1 L5)."""
    mdir = Path(manifest_dir).resolve()
    root = Path(repo_root).resolve()
    try:
        mdir.relative_to(root)
    except ValueError:
        return mdir
    try:
        mdir.relative_to(root / '.local-runs')
    except ValueError:
        raise CacheError('manifest dir %s is inside the checkout (outside .local-runs/)' % mdir)
    return mdir


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
    try:
        tmp.write_text(text)
        os.replace(str(tmp), str(path))
    except BaseException:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise


# ------------------------------------------------------------------ plan ----

PLAN_TIMEOUT_SECONDS = 120


class PlanTimeout(CacheError):
    """The plan overran its deadline (r1 M3): nothing is skipped."""


class _Deadline:
    """SIGALRM-based hard deadline for the compute phase of ``plan``.

    Raises PlanTimeout inside the guarded block when it overruns. A deadline
    that cannot be armed (not the main thread, no SIGALRM) raises CacheError
    up front, so the cache is off rather than unbounded.
    """

    def __init__(self, seconds):
        self.seconds = float(seconds)
        self.prev = None

    def _fire(self, _signum, _frame):
        raise PlanTimeout('plan timed out after %gs' % self.seconds)

    def __enter__(self):
        if not self.seconds > 0:
            raise CacheError('plan deadline must be positive, got %r' % self.seconds)
        try:
            self.prev = signal.signal(signal.SIGALRM, self._fire)
            signal.setitimer(signal.ITIMER_REAL, self.seconds)
        except (AttributeError, ValueError, OSError) as exc:
            raise CacheError('cannot arm the plan deadline: %s' % exc)
        return self

    def __exit__(self, *exc):
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, self.prev if self.prev is not None else signal.SIG_DFL)
        return False

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
        with _Deadline(getattr(args, 'timeout_seconds', PLAN_TIMEOUT_SECONDS)):
            keys, why, exes, skip, prior_note, new_lists = _plan_compute(args, env, now, sd, lookup)
    except (CacheError, ptb.PartitionError, OSError, ValueError) as exc:
        print('::warning::[%s] test-binary cache disabled for this run (%s): running every binary' % (ISSUE, exc))
        plan['reason'] = 'error: %s' % exc
        try:
            atomic_write(sd / 'cache_plan.json', json.dumps(plan, indent=1, sort_keys=True) + '\n')
        except OSError:
            pass
        return 0
    return _plan_apply(args, plan, sd, lookup, record, reason, keys, why, exes, skip, prior_note, new_lists)


def _plan_compute(args, env, now, sd, lookup):
    """Every read and hash of ``plan``; touches no file (runs under the deadline)."""
    build_lines = _read_lines(args.build_json)
    exes = ptb.parse_build_json(build_lines)
    rustc_vv = Path(args.rustc_vv).read_text()
    if not rustc_vv.strip():
        raise CacheError('rustc -Vv file is empty')
    cargo_v = cargo_version(args.cargo_v, env, cargo=args.cargo)
    server_fp = pg_fingerprint(env, psql=args.psql)
    keys, why = compute_keys(exes, build_lines, args.repo_root, rustc_vv, args.profile, env,
                             runtime=not args.no_runtime_tree, server_fp=server_fp, cargo_v=cargo_v)
    mdir = check_manifest_dir(resolve_manifest_dir(args.manifest_dir, env, args.repo_root), args.repo_root)
    mpath = manifest_path(mdir, args.node, args.tier, args.base_ref)
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
    return keys, why, exes, skip, prior_note, new_lists


def _plan_apply(args, plan, sd, lookup, record, reason, keys, why, exes, skip, prior_note, new_lists):
    """Write the plan outputs (deadline already disarmed).

    Order (r1 L3): the audit trail is printed and an enabled cache_plan.json
    and skip.txt are written BEFORE any list is shortened, then every
    ``.txt.full`` copy, then the lists. Any OSError on the way restores the
    full lists and disables the plan; if even that fails the exception
    propagates (non-zero exit), and the workflow runs ``restore`` or fails.
    """
    plan.update({
        'enabled': True, 'lookup': lookup, 'record': record, 'reason': reason, 'prior_note': prior_note,
        'run_id': args.run_id, 'sha': args.sha, 'keys': keys, 'key_errors': why,
        'skipped': {n: dict(e) for n, e in skip.items()},
    })
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
    sys.stdout.flush()
    try:
        atomic_write(sd / 'cache_plan.json', json.dumps(plan, indent=1, sort_keys=True) + '\n')
        atomic_write(sd / 'skip.txt', ''.join(sorted(n + '\n' for n in skip)))
        for n in SHARD_LISTS:
            atomic_write(sd / (n + '.txt.full'), (sd / (n + '.txt')).read_text())
        for n in SHARD_LISTS:
            atomic_write(sd / (n + '.txt'), ''.join(l + '\n' for l in new_lists[n]))
    except OSError as exc:
        print('::warning::[%s] test-binary cache disabled for this run (writing the shard lists failed: %s)'
              % (ISSUE, exc))
        _restore(sd, 'writing the shard lists failed: %s' % exc)
        return 0
    print('::notice::[%s] skipped %d of %d binaries (cache hits), running %d (%d without a computable key; prior manifest: %s)'
          % (ISSUE, n_skip, n_total, n_total - n_skip, n_nokey, prior_note))
    return 0


# --------------------------------------------------------------- restore ----

def _restore(sd, reason):
    """Write a disabled plan, then copy every ``<list>.txt.full`` back.

    The disabled plan goes first, so ``record`` refuses even when a list copy
    then fails.
    """
    plan = {'schema': SCHEMA, 'enabled': False, 'lookup': False, 'record': False, 'keys': {}, 'skipped': {},
            'reason': reason}
    atomic_write(sd / 'cache_plan.json', json.dumps(plan, indent=1, sort_keys=True) + '\n')
    atomic_write(sd / 'skip.txt', '')
    restored = []
    for n in SHARD_LISTS:
        full = sd / (n + '.txt.full')
        if full.is_file():
            atomic_write(sd / (n + '.txt'), full.read_text())
            restored.append(n)
    return restored


def run_restore(args):
    """Put every ``<list>.txt.full`` back and write a disabled plan (r1 M3).

    The workflow calls this when ``plan`` exits non-zero or is killed by the
    outer watchdog, so a half-finished plan can never leave a shortened list.
    A list without a ``.txt.full`` was never rewritten (the full copy is
    written before the list is replaced) and is left as it is. Raises on any
    write failure: the workflow then fails the step instead of running a
    list it cannot vouch for.
    """
    restored = _restore(Path(args.shard_dir), 'restored after a failed or timed-out plan')
    print('::warning::[%s] test-binary cache plan did not finish: full shard lists restored (%s); running every binary'
          % (ISSUE, ', '.join(restored) or 'none were rewritten'))
    return 0


# ---------------------------------------------------------------- record ----

class _Lock:
    """Exclusive advisory lock on ``path``. Fails closed (r1 L4): when the
    lock cannot be taken, CacheError is raised and nothing is recorded."""

    def __init__(self, path):
        self.path = path
        self.fh = None

    def __enter__(self):
        try:
            import fcntl
        except ImportError as exc:
            raise CacheError('no advisory locks on this platform: %s' % exc)
        try:
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
            self.fh = open(self.path, 'a')
            fcntl.flock(self.fh, fcntl.LOCK_EX)
        except OSError as exc:
            if self.fh is not None:
                self.fh.close()
                self.fh = None
            raise CacheError('cannot lock %s: %s' % (self.path, exc))
        return self

    def __exit__(self, *exc):
        if self.fh is not None:
            self.fh.close()
        return False


SWEEP_MANIFEST_RE = re.compile(r'^test-manifest-.*\.json$')
SWEEP_TMP_RE = re.compile(r'^\.test-manifest-.*\.json\.\d+\.tmp$')


def sweep_manifest_dir(manifest_dir, keep, wall_now=None):
    """Remove manifests, locks and temp files older than 7 days (r1 L4).

    Ages come from file mtimes against the wall clock. ``keep`` (the manifest
    just written) and its lock are never removed. A lock goes only when its
    manifest is gone and a non-blocking flock on it succeeds (nobody holds
    it). Only files named like this script's own files are touched; every
    error is ignored (a sweep never affects the record). Returns the count.
    """
    wall_now = time.time() if wall_now is None else wall_now
    mdir = Path(manifest_dir)
    keep = Path(keep)
    removed = 0
    try:
        entries = sorted(mdir.iterdir())
    except OSError:
        return 0

    def old(path):
        try:
            st = os.lstat(str(path))
        except OSError:
            return False
        return stat.S_ISREG(st.st_mode) and wall_now - st.st_mtime > MAX_AGE_SECONDS

    for path in entries:
        name = path.name
        if path == keep or not (SWEEP_MANIFEST_RE.match(name) or SWEEP_TMP_RE.match(name)):
            continue
        if old(path):
            try:
                path.unlink()
                removed += 1
            except OSError:
                pass
    for path in entries:
        name = path.name
        if not name.endswith('.json.lock') or not SWEEP_MANIFEST_RE.match(name[:-len('.lock')]):
            continue
        manifest = path.with_name(name[:-len('.lock')])
        if manifest == keep or manifest.exists() or not old(path):
            continue
        try:
            import fcntl
            with open(str(path), 'a') as fh:
                fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
                path.unlink()
                removed += 1
        except (ImportError, OSError):
            pass
    return removed


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
    repo_root = getattr(args, 'repo_root', '.') or '.'
    try:
        mdir = check_manifest_dir(resolve_manifest_dir(args.manifest_dir, dict(os.environ), repo_root), repo_root)
    except CacheError as exc:
        print('::warning::[%s] test-binary cache not recorded: %s' % (ISSUE, exc))
        return 0
    mpath = manifest_path(mdir, node, tier, base)
    try:
        lock = _Lock(str(mpath) + '.lock').__enter__()
    except CacheError as exc:
        print('::warning::[%s] test-binary cache not recorded: %s (lookup is unaffected)' % (ISSUE, exc))
        return 0
    try:
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
        swept = sweep_manifest_dir(mpath.parent, mpath)
    finally:
        lock.__exit__(None, None, None)
    print('::notice::[%s] test-binary cache recorded: %d pass, %d without key (%d entries in %s; swept %d old files)'
          % (ISSUE, recorded, dropped, len(entries), mpath.name, swept))
    return 0


# ------------------------------------------------------------------- cli ----

def build_parser():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    sub = ap.add_subparsers(dest='cmd', required=True)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument('--shard-dir', required=True)
    common.add_argument('--manifest-dir', default='',
                        help='manifest directory (default: see resolve_manifest_dir)')
    common.add_argument('--run-id', default='')
    common.add_argument('--sha', default='')
    pl = sub.add_parser('plan', parents=[common])
    pl.add_argument('--build-json', required=True)
    pl.add_argument('--repo-root', default='.')
    pl.add_argument('--rustc-vv', required=True, help='file holding `rustc -Vv` output (written by the workflow)')
    pl.add_argument('--cargo-v', default='',
                    help='file holding `cargo -V` output (written by the workflow); without it cargo is asked')
    pl.add_argument('--cargo', default='cargo', help='cargo asked for its version when --cargo-v is not given')
    pl.add_argument('--profile', default='', help='feature/profile string, e.g. "test sal-postgres"')
    pl.add_argument('--tier', required=True)
    pl.add_argument('--node', required=True)
    pl.add_argument('--base-ref', required=True)
    pl.add_argument('--event', required=True)
    pl.add_argument('--ref', default='')
    pl.add_argument('--psql', default='psql', help='psql used for the Postgres server fingerprint')
    pl.add_argument('--no-runtime-tree', action='store_true',
                    help='TESTS ONLY: skip the run-time file tree digest (never set by the workflow)')
    pl.add_argument('--timeout-seconds', type=float, default=PLAN_TIMEOUT_SECONDS,
                    help='hard deadline for computing the plan; on expiry nothing is skipped')
    rs = sub.add_parser('restore', help='put the full shard lists back after a failed plan')
    rs.add_argument('--shard-dir', required=True)
    rc = sub.add_parser('record', parents=[common])
    rc.add_argument('--rc', type=int, required=True, help='exit code of the test step; must be 0')
    rc.add_argument('--repo-root', default='.')
    return ap


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.cmd == 'plan':
        return run_plan(args)
    if args.cmd == 'restore':
        return run_restore(args)
    return run_record(args)


if __name__ == '__main__':
    sys.exit(main())
