#!/usr/bin/env python3
r"""#3733 gate -- INVARIANT: a test that creates a directory it then uses as a key dir MUST create it
through tests/common/key_dir_sandbox.rs::mkdir_0700 (create + chmod 0700), NEVER a bare
std::fs::create_dir[_all].

This is not a failure prediction. A bare-created key dir is 0o755 at umask 022 (the author's
machine) but 0o775 -- group-writable -- at umask 0002 (this host and most user-private-group
distros), and the #3198 key-dir guard CORRECTLY refuses a group-writable key dir. A fixture that
skips the chmod is wrong whether or not its current assertions notice: the next assertion added to
it will fail, pointing at a product check that is working (the #3733 confusing-failure shape).

Scope of the match, stated honestly (the shell version this replaces claimed to be "CORRELATED so it
only fires on the SAME token bare-created AND passed as the key dir" -- its two greps correlate only
by FILE, not by token, and nothing in it compared the captured names; the prose overclaimed what the
code did). This gate fires when, in one file that references a key-dir env var and does not use the
sandbox helper, there is BOTH a bare create of a key-dir-shaped name AND a key-dir-shaped value
passed as the env var. That is deliberately fail-closed: a false positive costs one allowlisted
helper call, a false negative costs a confusing failure in someone else's lane.

#4501 class, fixed here: the shell predicate this replaces was a line-based `grep -qE`, so a
rustfmt-wrapped call -- which is what rustfmt produces as soon as the line passes the width limit --
read clean. A formatter pass must never be able to blind a gate. The fix is simply that these
patterns are matched against the WHOLE FILE, where `\s*` spans newlines; no line joining is needed,
and an earlier draft that added a continuation-joiner was removed when a mutation showed the
wrapped-call cell passed identically without it (an untested code path is a liability, not a
safeguard). Cell 6 pins the wrapped shape, and the line-based negative control beside it pins WHY
the line-based form is not allowed back: it misses that same cell.

Usage:
  scripts/check-test-keydir-mode.py              # scan tests/ -- exit 1 on any violation
  scripts/check-test-keydir-mode.py --self-test  # fixtures under .local-runs/, never /tmp
  scripts/check-test-keydir-mode.py --only tests/foo.rs
Cargo-free, stdlib python3 only.
"""
import argparse, os, pathlib, re, subprocess, sys

SANDBOX = re.compile(r'mkdir_0700|from_mode\(0o700\)')
REFERENCES_KEY_DIR = re.compile(r'AI_MEMORY_KEY_DIR|_KEY_DIR"')
BARE_CREATE = re.compile(r'(?:std::)?fs::create_dir(?:_all)?\(\s*&?\s*(keys|key_dir|kdir|dir)\b')
PASSED_AS_KEY_DIR = [
    re.compile(r'KEY_DIR"?\s*,\s*&?\s*(keys|key_dir|kdir|dir)\b'),
    re.compile(r'KEY_DIR"\s*,\s*[a-z_]+(?:\.path\(\))?\.join\("keys"\)'),
    re.compile(r'self\.keys'),
]

def sandboxed(text: str, tok: str) -> bool:
    """Is THIS token the one the sandbox helper created?

    The replaced shell gate exempted a whole FILE that mentioned mkdir_0700 anywhere, so a fixture
    with one sandboxed key dir and a second bare-created one was exempt (reviewer-f2r, N2). The
    exemption is now per token, and it only narrows the file-level rule where the file mentions the
    helper at all -- a file with no sandbox mention keeps the old, looser trigger, so this is
    strictly more sensitive than before and never less.
    """
    t = re.escape(tok)
    return bool(re.search(rf'mkdir_0700\s*\(\s*&?\s*{t}\b', text)
                or re.search(rf'\b{t}\s*=\s*[^;]*mkdir_0700', text)
                or re.search(rf'from_mode\(0o700\)[^;]*\b{t}\b', text)
                or re.search(rf'\b{t}\b[^;]*from_mode\(0o700\)', text))

def passed_as(text: str, tok: str) -> 're.Match | None':
    t = re.escape(tok)
    return (re.search(rf'KEY_DIR"?\s*,\s*&?\s*{t}\b', text)
            or (re.search(r'KEY_DIR"\s*,\s*[a-z_]+(?:\.path\(\))?\.join\("keys"\)', text) if tok == 'keys' else None)
            or (re.search(r'self\.keys', text) if tok == 'keys' else None))

def scan_text(name: str, text: str) -> list[str]:
    if not REFERENCES_KEY_DIR.search(text):
        return []
    bare = [m for m in BARE_CREATE.finditer(text)]
    if SANDBOX.search(text):
        # the file uses the helper: judge TOKEN BY TOKEN, so a second, unsandboxed key dir still fires
        created = next((m for m in bare if not sandboxed(text, m.group(1)) and passed_as(text, m.group(1))), None)
        passed = passed_as(text, created.group(1)) if created else None
    else:
        created = bare[0] if bare else None
        passed = next((p.search(text) for p in PASSED_AS_KEY_DIR if p.search(text)), None)
    if created and passed:
        return [f'INVARIANT VIOLATION ({name}): a test that creates a key directory must use\n'
                f'  key_dir_sandbox::mkdir_0700 (create + chmod 0700), not a bare create_dir --\n'
                f'  otherwise the key dir inherits the umask (0o775 @umask0002) and the #3198\n'
                f'  guard refuses it. Fix the FIXTURE, never the product (#3733).\n'
                f'  bare create: {created.group(0)}   passed as key dir: {passed.group(0)}']
    return []

def line_based_match(text: str) -> bool:
    """The replaced shell gate's semantics: the same patterns, applied one line at a time.

    Used ONLY by the self-test, as the negative control that keeps the regression from coming back:
    a wrapped call matches whole-file and does NOT match line-by-line, so a cell that is VIOLATION
    under scan_text and clean here is exactly the coverage the port adds.
    """
    if not REFERENCES_KEY_DIR.search(text) or SANDBOX.search(text):
        return False
    lines = text.splitlines()
    return (any(BARE_CREATE.search(l) for l in lines)
            and any(p.search(l) for p in PASSED_AS_KEY_DIR for l in lines))

class ScanError(RuntimeError):
    """The corpus could not be enumerated. Never reported as a clean scan."""

def candidates() -> list[pathlib.Path]:
    """Tracked AND untracked test files that reference a key-dir env var.

    git grep's exit status is LOAD-BEARING: 0 = matches, 1 = no match, >=2 (128 in practice) = error.
    The first version of this port ignored it, so `GIT_DIR=/nonexistent` printed
    "ok: ... (0 file(s) scanned)" and exited 0 -- a gate reporting green over a scan that never
    happened, the #4090 class, found by reviewer-f2r. An error is fatal now, and so is an EMPTY
    candidate set: this corpus has ~75 such files, so zero means the scan broke rather than that the
    invariant holds. `--untracked` is passed because a NEW test file is exactly where this violation
    gets introduced, and git grep would otherwise skip it until it was committed (f2r, N1).
    """
    r = subprocess.run(['git', 'grep', '-l', '--untracked', '-E', 'AI_MEMORY_KEY_DIR|_KEY_DIR"', '--',
                        'tests/*.rs', 'tests/**/*.rs'], capture_output=True, text=True)
    if r.returncode >= 2:
        raise ScanError(f'git grep failed (rc={r.returncode}): {(r.stderr or r.stdout).strip()[:200]}')
    return sorted({pathlib.Path(p) for p in r.stdout.split()})

CELLS = [
    ('bare create + key dir passed, one line', True, '''
        let keys = tmp.path().join("keys");
        std::fs::create_dir(&keys).unwrap();
        cmd.env("AI_MEMORY_KEY_DIR", &keys);
    '''),
    ('same fixture through mkdir_0700', False, '''
        let keys = mkdir_0700(&tmp.path().join("keys"));
        cmd.env("AI_MEMORY_KEY_DIR", &keys);
    '''),
    ('same fixture through from_mode(0o700)', False, '''
        let keys = tmp.path().join("keys");
        std::fs::create_dir(&keys).unwrap();
        std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o700)).unwrap();
        cmd.env("AI_MEMORY_KEY_DIR", &keys);
    '''),
    ('bare create of an unrelated dir, key dir is the TempDir root', False, '''
        let data = tmp.path().join("data");
        std::fs::create_dir(&data).unwrap();
        cmd.env("AI_MEMORY_KEY_DIR", tmp.path());
    '''),
    ('env value is tmp.path().join("keys"), dir bare-created', True, '''
        let keys = tmp.path().join("keys");
        std::fs::create_dir_all(&keys).unwrap();
        cmd.env("AI_MEMORY_KEY_DIR", tmp.path().join("keys"));
    '''),
    ('rustfmt-wrapped create call (#4501 class)', True, '''
        let key_dir = tmp.path().join("keys");
        std::fs::create_dir_all(
            &key_dir,
        )
        .unwrap();
        cmd.env(
            "AI_MEMORY_KEY_DIR",
            &key_dir,
        );
    '''),
    ('file that never mentions a key dir', False, '''
        let data = tmp.path().join("data");
        std::fs::create_dir(&data).unwrap();
    '''),
    ('sandboxed key dir AND a second bare-created one (f2r N2)', True, '''
        let keys = mkdir_0700(&tmp.path().join("keys"));
        cmd.env("AI_MEMORY_KEY_DIR", &keys);
        let kdir = tmp.path().join("kdir");
        std::fs::create_dir(&kdir).unwrap();
        other.env("AI_MEMORY_KEY_DIR", &kdir);
    '''),
    ('sandboxed key dir plus a bare-created UNRELATED dir', False, '''
        let keys = mkdir_0700(&tmp.path().join("keys"));
        cmd.env("AI_MEMORY_KEY_DIR", &keys);
        let data = tmp.path().join("data");
        std::fs::create_dir(&data).unwrap();
    '''),
]

def self_test(out_dir: pathlib.Path) -> int:
    out_dir.mkdir(parents=True, exist_ok=True)
    passed = failed = 0
    for i, (name, want_violation, body) in enumerate(CELLS, 1):
        src = f'#[test]\nfn cell_{i}() {{{body}}}\n'
        f = out_dir / f'cell_{i}.rs'
        f.write_text(src)
        got = bool(scan_text(str(f), src))
        legacy = line_based_match(src)
        ok = got == want_violation
        passed, failed = passed + ok, failed + (not ok)
        delta = '' if legacy == got else ('   <- line-based form MISSES this' if got else
                                          '   <- line-based form false-positives here')
        print(f'  [{"ST-ok" if ok else "ST-FAIL"}] cell {i}: {name} -> '
              f'{"VIOLATION" if got else "clean"} (want {"VIOLATION" if want_violation else "clean"})'
              f'{delta}')
    # The port must add coverage, not merely pass: at least one cell must be caught whole-file and
    # missed line-by-line, or the #4501 fix is not actually exercised by this self-test.
    added = [i for i, (_n, want, body) in enumerate(CELLS, 1)
             if want and scan_text('x', f'#[test]\nfn c() {{{body}}}\n')
             and not line_based_match(f'#[test]\nfn c() {{{body}}}\n')]
    # ---- the ENUMERATION, end to end (reviewer-f2r's B1/N1) ----------------------------------
    # scan_text cells prove the predicate. These prove the gate cannot report clean when the corpus
    # was never enumerated -- the defect f2r found: GIT_DIR=/nonexistent printed
    # "ok: ... (0 file(s) scanned)" with rc 0.
    import tempfile
    me = str(pathlib.Path(__file__).resolve())
    VIOL = ('#[test]\nfn t() {\n    let keys = tmp.path().join("keys");\n'
            '    std::fs::create_dir(&keys).unwrap();\n    cmd.env("AI_MEMORY_KEY_DIR", &keys);\n}\n')
    def run_in(cwd, env=None, args=()):
        e = dict(os.environ); e.pop('GIT_DIR', None)
        if env: e.update(env)
        r = subprocess.run([sys.executable, me, *args], cwd=cwd, env=e, capture_output=True, text=True)
        return r.returncode, (r.stdout + r.stderr)
    def mkrepo(d, files):
        subprocess.run(['git', 'init', '-q', d], check=True)
        for rel, body in files.items():
            f = pathlib.Path(d, rel); f.parent.mkdir(parents=True, exist_ok=True); f.write_text(body)
        return d
    scan_cells = []
    with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR', '/mnt/t9/tmp/god-f2')) as d:
        rc, out = run_in(str(pathlib.Path(me).parent.parent), env={'GIT_DIR': '/nonexistent'})
        scan_cells.append(('a broken git dir is an ERROR, not a clean scan', rc == 2 and 'SCAN FAILED' in out, f'rc={rc}'))
        empty = mkrepo(os.path.join(d, 'empty'), {'tests/unrelated.rs': 'fn t() {}\n'})
        rc, out = run_in(empty)
        scan_cells.append(('an EMPTY candidate set is an ERROR, not a clean scan', rc == 2 and 'SCAN EMPTY' in out, f'rc={rc}'))
        untr = mkrepo(os.path.join(d, 'untracked'), {'tests/new_fixture.rs': VIOL})
        rc, out = run_in(untr)
        scan_cells.append(('an UNTRACKED new test file is scanned (--untracked)', rc == 1 and 'INVARIANT VIOLATION' in out, f'rc={rc}'))
        trk = mkrepo(os.path.join(d, 'tracked'), {'tests/committed.rs': VIOL})
        subprocess.run(['git', '-C', trk, 'add', '-A'], check=True)
        rc, out = run_in(trk)
        scan_cells.append(('a TRACKED test file is scanned (control)', rc == 1 and 'INVARIANT VIOLATION' in out, f'rc={rc}'))
    for name, ok, detail in scan_cells:
        passed, failed = passed + ok, failed + (not ok)
        print(f'  [{"ST-ok" if ok else "ST-FAIL"}] scan: {name} ({detail})')

    print(f'check-test-keydir-mode self-test: {passed} passed, {failed} failed '
          f'(fixtures under {out_dir})')
    if not added:
        print('  ST-FAIL: no cell distinguishes whole-file matching from the line-based form -- '
              'the #4501 coverage this port adds is unproven')
        failed += 1
    else:
        print(f'  coverage added over the line-based form: cell(s) {added}')
    return 1 if failed else 0

ap = argparse.ArgumentParser(add_help=True)
ap.add_argument('--self-test', action='store_true')
ap.add_argument('--only', default=None)
ap.add_argument('--selftest-dir', default='.local-runs/selftest-keydir')
a = ap.parse_args()

if a.self_test:
    sys.exit(self_test(pathlib.Path(a.selftest_dir)))

if a.only:
    files = [pathlib.Path(a.only)]
else:
    try:
        files = candidates()
    except ScanError as ex:
        print(f'SCAN FAILED: {ex}\n  refusing to report a clean tree over a scan that did not run (#4090 class)')
        sys.exit(2)
    if not files:
        print('SCAN EMPTY: no tests/*.rs file references a key-dir env var.\n'
              '  This corpus has ~75 of them, so an empty candidate set means the scan broke, not\n'
              '  that the invariant holds. Refusing to report clean (#4090 class).')
        sys.exit(2)
fail = 0
for f in files:
    for v in scan_text(str(f), f.read_text(errors='replace')):
        print(v)
        fail = 1
if not fail:
    print(f'ok: every key-dir-creating test uses mkdir_0700 ({len(files)} file(s) scanned)')
sys.exit(fail)
