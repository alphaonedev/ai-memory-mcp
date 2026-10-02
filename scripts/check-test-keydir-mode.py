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
import argparse, pathlib, re, subprocess, sys

SANDBOX = re.compile(r'mkdir_0700|from_mode\(0o700\)')
REFERENCES_KEY_DIR = re.compile(r'AI_MEMORY_KEY_DIR|_KEY_DIR"')
BARE_CREATE = re.compile(r'(?:std::)?fs::create_dir(?:_all)?\(\s*&?\s*(keys|key_dir|kdir|dir)\b')
PASSED_AS_KEY_DIR = [
    re.compile(r'KEY_DIR"?\s*,\s*&?\s*(keys|key_dir|kdir|dir)\b'),
    re.compile(r'KEY_DIR"\s*,\s*[a-z_]+(?:\.path\(\))?\.join\("keys"\)'),
    re.compile(r'self\.keys'),
]

def scan_text(name: str, text: str) -> list[str]:
    if not REFERENCES_KEY_DIR.search(text):
        return []
    if SANDBOX.search(text):
        return []
    created = BARE_CREATE.search(text)
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

def candidates() -> list[pathlib.Path]:
    r = subprocess.run(['git', 'grep', '-lE', 'AI_MEMORY_KEY_DIR|_KEY_DIR"', '--',
                        'tests/*.rs', 'tests/**/*.rs'], capture_output=True, text=True)
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

files = [pathlib.Path(a.only)] if a.only else candidates()
fail = 0
for f in files:
    for v in scan_text(str(f), f.read_text(errors='replace')):
        print(v)
        fail = 1
if not fail:
    print(f'ok: every key-dir-creating test uses mkdir_0700 ({len(files)} file(s) scanned)')
sys.exit(fail)
