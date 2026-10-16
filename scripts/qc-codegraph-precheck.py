#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""C8 orchestrator safeguard (CLAUDE.md "Enforceable Orchestrator Safeguards", #923 + #953).

HARD-BLOCK any new ``CallerContext::for_agent("<literal>")`` site outside the
allowlist, and any new ``CallerContext::for_admin(...)`` privacy-bypass site
outside its allowlist.

Python port of ``scripts/qc-codegraph-precheck.sh`` (#7260, Python-not-shell).
Same checks, same output lines, same exit codes:

    0  clean
    1  violation (a HARD-BLOCK category fired)
    2  setup error (allowlist dir or files missing, or a pinned path missing)

Usage::

    scripts/qc-codegraph-precheck.py              # check
    scripts/qc-codegraph-precheck.py --update     # regenerate allowlists from the current state
    scripts/qc-codegraph-precheck.py --self-test  # prove the detectors are load-bearing

What it checks:

* every production line in ``src/`` matching ``CallerContext::for_agent("<lit>")``
  (a static string, not a variable) and every ``CallerContext::for_admin(`` call in
  any argument form (#1651); test items are blanked by :func:`production_lines`;
* each surviving site must appear in its allowlist;
* ``for_admin_checked(.., <literal bool>)`` in production (#3943);
* every SQLite write transaction opens ``BEGIN IMMEDIATE`` (#5084).

Fail closed (#7260): the ``src/`` scan root is pinned through
``scripts/ci/pathpin.py``. A missing ``src/``, or one with no ``.rs`` file, is
exit 2, never a pass. In a real checkout (a ``Cargo.toml`` at the root) the
files this gate names literally, the exemption file and the write-transaction
home, are pinned too; a synthetic fixture tree (the #3623 harness) has no
``Cargo.toml`` and is exempt from those two pins only.

Standard library only, Python 3.9+.
"""
import argparse
import re
import subprocess
import sys
from pathlib import Path
from typing import List, Optional, Tuple

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent / 'ci'))
import pathpin  # noqa: E402  (path set above)

EXIT_OK = 0
EXIT_VIOLATION = 1
EXIT_SETUP = 2

SELF = 'scripts/qc-codegraph-precheck.py'
SRC_REL = 'src'
RS_GLOB = '*.rs'
CARGO_TOML = 'Cargo.toml'
ALLOW_DIR = ROOT / 'scripts' / 'qc-codegraph-allowlists'
ALLOW_FOR_AGENT = ALLOW_DIR / 'caller-context-literals.txt'
ALLOW_FOR_ADMIN = ALLOW_DIR / 'for-admin-bypass.txt'
CHECKED_LITERAL_SCRIPT = ROOT / 'scripts' / 'tests' / 'for-admin-checked-literal-3943.py'
WRITE_TXN_SCRIPT = ROOT / 'scripts' / 'check-sqlite-write-txn-immediate.py'
HARNESS_SCRIPT = ROOT / 'scripts' / 'tests' / 'gate-production-3623.py'
WRITE_TXN_HOME = 'src/storage/connection.rs'

FOR_AGENT = 'CallerContext::for_agent'
FOR_ADMIN = 'CallerContext::for_admin'
MODE_LITERAL = 'literal'
MODE_ANY_ARG = 'any-arg'

# #5884 — the one #3638-adjudicated for_admin(GOVERNANCE_INTERNAL) site is
# exempt by CONTENT: file, the exact source line, and the function that encloses
# it. No line number is pinned (a pin goes stale on every edit above it and then
# silently stops matching). Closed world: the exemption applies only when the
# file holds EXACTLY ONE copy of the line and that copy sits inside the anchor
# function. Zero copies (moved or reworded), two or more (duplicated), or a copy
# in another function is a HARD-BLOCK that names the file and the count; the
# site is then not exempt. scripts/tests/gate-production-3623.py reads these
# three constants from this file so the fixtures cannot drift from the gate.
C8_EXEMPT_FILE = 'src/store/postgres.rs'
C8_EXEMPT_FN = 'resolve_governance_policy'
C8_EXEMPT_LINE = '            let ctx = CallerContext::for_admin(crate::identity::sentinels::GOVERNANCE_INTERNAL);'

WS = r'[ \t\n\r\f\v]'
TEST_STEM = re.compile(r'(^|_)tests?(_|$)')
FN_DECL = re.compile(r'^' + WS + r'*(pub(\([^)]*\))?' + WS + r'+)?((async|unsafe|const)' + WS + r'+)*fn' + WS + r'+[A-Za-z_]')
FN_PREFIX = re.compile(r'^' + WS + r'*(pub(\([^)]*\))?' + WS + r'+)?((async|unsafe|const)' + WS + r'+)*fn' + WS + r'+')
COMMENT_LINE = re.compile(r'^' + WS + r'*(//|\*)')
SKIP_LINE_END = re.compile(r';' + WS + r'*(//.*)?$')
CLOSE_BRACE = re.compile(r'^\}[;]?' + WS + r'*(//.*)?$')
INLINE_BRACES = re.compile(r'\{.*\}[;]?' + WS + r'*(//.*)?$')


class SetupError(Exception):
    """A setup problem (exit 2): missing allowlists, missing pinned path."""


def is_test_stem(stem: str) -> bool:
    return TEST_STEM.search(stem) is not None


def production_lines(path: str, text: str) -> List[str]:
    """Blank test items without changing line numbers (port of production-lines.awk, #3623).

    rustfmt aligns an item's closing brace with its attribute. Unknown cfg
    expressions stay visible: ``cfg(any(test, feature = ...))`` can be production code.
    """
    lines = text.split('\n')
    if lines and lines[-1] == '':
        lines.pop()
    if is_test_stem(Path(path).stem):
        return [''] * len(lines)
    out: List[str] = []
    whole_file = False
    skipping = False
    opened = False
    anchor = 0
    for line in lines:
        current = line
        if re.match(r'^' + WS + r'*#!\[cfg\(test\)\]', line):
            whole_file = True
        stripped = re.sub(r'^' + WS + r'*', '', line)
        indent = len(line) - len(stripped)
        if not skipping and stripped.startswith('#[cfg(test)]'):
            skipping, anchor = True, indent
        if not skipping and re.match(r'^#\[cfg\(all\(test[,)]', stripped):
            skipping, anchor = True, indent
        if skipping:
            current = ''
            stripped = re.sub(r'^#\[cfg\(test\)\]' + WS + r'*', '', stripped)
            if stripped.startswith('#') or stripped.startswith('//') or stripped == '':
                out.append(current)
                continue
            if not opened and '{' in stripped:
                opened = True
            if ((not opened and SKIP_LINE_END.search(stripped))
                    or (opened and indent == anchor and CLOSE_BRACE.match(stripped))
                    or (opened and indent == anchor and INLINE_BRACES.search(stripped))):
                skipping = False
                opened = False
        out.append(current)
    return [''] * len(out) if whole_file else out


def read_source(path: Path) -> str:
    # Bytes, not read_text: universal newlines would fold CRLF and hide a CR from the pinned-line compare.
    return path.read_bytes().decode('utf-8', errors='replace')


def rust_files(root: Path) -> List[Path]:
    return sorted(p for p in (root / SRC_REL).rglob(RS_GLOB) if p.is_file())


def pin_scan_root(root: Path) -> None:
    """The scan root must exist and hold Rust files (#7260): zero files scanned is exit 2."""
    try:
        pathpin.pin_path(root, SRC_REL, glob=RS_GLOB)
    except pathpin.PinError as err:
        raise SetupError(f'{err}; the C8 scan would cover nothing') from None


def exemption_state(root: Path) -> Tuple[Optional[int], str]:
    """Return (exempt line number or None, error text) for the pinned #5884 site."""
    path = root / C8_EXEMPT_FILE
    if not path.is_file():
        if (root / CARGO_TOML).is_file():
            raise SetupError(f'pathpin: missing path {C8_EXEMPT_FILE} under {root}; the GOVERNANCE_INTERNAL'
                             ' exemption anchor moved (update C8_EXEMPT_FILE with it)')
        return None, ''
    count = 0
    lineno = 0
    fn_at_site = ''
    current_fn = ''
    for number, line in enumerate(production_lines(str(path), read_source(path)), 1):
        if FN_DECL.match(line):
            rest = FN_PREFIX.sub('', line, count=1)
            found = re.match(r'[A-Za-z0-9_]+', rest)
            current_fn = found.group(0) if found else ''
        if line == C8_EXEMPT_LINE:
            count += 1
            lineno = number
            fn_at_site = current_fn
    if count != 1:
        return None, (f'exemption for {C8_EXEMPT_FILE} needs exactly 1 match of the pinned line, found {count}')
    if fn_at_site != C8_EXEMPT_FN:
        return None, (f'exemption for {C8_EXEMPT_FILE} needs exactly 1 match inside fn {C8_EXEMPT_FN},'
                      f' found {count} (inside fn {fn_at_site or "none"})')
    return lineno, ''


def extract_literal(pattern: str, content: str, mode: str, raw_lines: List[str], lineno: int) -> str:
    """Port of the sed pipeline: the literal, or in any-arg mode the argument expression."""
    found = re.search(r'.*' + re.escape(pattern) + r'\("([^"]+)"\)', content)
    literal = found.group(1) if found else ''
    if not literal and mode == MODE_ANY_ARG:
        found = re.search(r'.*' + re.escape(pattern) + r'\(([^")(,]+)[,)]', content)
        literal = found.group(1).replace(' ', '').replace('&', '') if found else ''
        if not literal and re.search(re.escape(pattern) + r'\($', content):
            # Call split across lines (rustfmt reflow): the first token of the next source line.
            nextline = raw_lines[lineno] if lineno < len(raw_lines) else ''
            quoted = re.match(r'^' + WS + r'*"([^"]+)"', nextline)
            literal = quoted.group(1) if quoted else ''
            if not literal:
                bare = re.match(r'^' + WS + r'*([A-Za-z0-9_:&]+)', nextline)
                literal = bare.group(1).replace('&', '') if bare else ''
        literal = literal.rsplit('::', 1)[-1]
    return literal


def collect_sites(root: Path, pattern: str, mode: str, exempt_lineno: Optional[int]) -> List[str]:
    """Enumerate production sites as sorted unique ``file:line:literal`` entries."""
    needle = pattern + ('(' if mode == MODE_ANY_ARG else '("')
    found: List[str] = []
    for path in rust_files(root):
        text = read_source(path)
        production = production_lines(str(path), text)
        raw_lines = text.split('\n')
        rel = path.relative_to(root).as_posix()
        for lineno, content in enumerate(production, 1):
            if needle not in content or COMMENT_LINE.match(content):
                continue
            literal = extract_literal(pattern, content, mode, raw_lines, lineno)
            if not literal:
                continue
            if (mode == MODE_ANY_ARG and rel == C8_EXEMPT_FILE and exempt_lineno is not None
                    and lineno == exempt_lineno and content == C8_EXEMPT_LINE):
                continue
            found.append(f'{rel}:{lineno}:{literal}')
    return sorted(set(found))


def strip_line(sites: List[str]) -> List[str]:
    """Drop the line-number column: the allowlist contract is ``file:literal`` only."""
    out = []
    for site in sites:
        out.append(re.sub(r'^([^:]+):[0-9]+:(.*)$', r'\1:\2', site))
    return sorted(set(out))


def allowlist_body(path: Path) -> List[str]:
    lines = [ln for ln in read_source(path).split('\n') if ln != '' and not ln.startswith('#')]
    return sorted(set(lines))


def write_allowlist(path: Path, payload: List[str], title: str) -> None:
    header = (f'# {title}\n'
              f'# Auto-generated by {SELF} --update.\n'
              '# Format: <repo-root-relative-file>:<literal>\n'
              '# Edit deliberately — every entry should be a reviewed exception.\n'
              '# See CLAUDE.md §"Enforceable Orchestrator Safeguards" (C8).\n'
              '\n')
    path.write_text(header + '\n'.join(payload) + '\n', encoding='utf-8')


def check_diff(label: str, current: List[str], allow: List[str]) -> int:
    """Return 1 when new sites exist (a violation category); stale entries only WARN."""
    violation = 0
    new_sites = sorted(set(current) - set(allow))
    if new_sites:
        print(f'C8 HARD-BLOCK: new {label} site(s) not in allowlist:', file=sys.stderr)
        for site in new_sites:
            print(f'  {site}', file=sys.stderr)
        print('', file=sys.stderr)
        print('If these are deliberate exceptions, run:', file=sys.stderr)
        print(f'  {SELF} --update', file=sys.stderr)
        print(f'and review the diff to {str(ALLOW_DIR).rstrip("/")}/*.txt before committing.', file=sys.stderr)
        violation = 1
    stale = sorted(set(allow) - set(current))
    if stale:
        print(f'C8 WARN: stale {label} allowlist entries (no longer present in source):', file=sys.stderr)
        for site in stale:
            print(f'  {site}', file=sys.stderr)
        print(f'  → run `{SELF} --update` to prune.', file=sys.stderr)
    return violation


def checked_literal_hits(root: Path) -> List[str]:
    """#3943: a literal bool in the second argument of ``for_admin_checked(`` severs the admin gate."""
    hits: List[str] = []
    for path in rust_files(root):
        text = read_source(path)
        if 'for_admin_checked(' not in text:
            continue
        production = '\n'.join(production_lines(str(path), text)) + '\n'
        run = subprocess.run([sys.executable, str(CHECKED_LITERAL_SCRIPT), path.relative_to(root).as_posix()],
                             input=production, capture_output=True, text=True, check=False)
        hits.extend(line for line in run.stdout.split('\n') if line)
    return hits


def run_check(update: bool) -> int:
    if not ALLOW_DIR.is_dir():
        print(f'ERROR: allowlist dir missing: {ALLOW_DIR}', file=sys.stderr)
        return EXIT_SETUP
    try:
        pin_scan_root(ROOT)
        exempt_lineno, exempt_err = exemption_state(ROOT)
        real_checkout = (ROOT / CARGO_TOML).is_file()
        if real_checkout:
            pathpin.pin_path(ROOT, WRITE_TXN_HOME)
    except (SetupError, pathpin.PinError) as err:
        print(str(err), file=sys.stderr)
        return EXIT_SETUP
    for_agent = strip_line(collect_sites(ROOT, FOR_AGENT, MODE_LITERAL, exempt_lineno))
    for_admin = strip_line(collect_sites(ROOT, FOR_ADMIN, MODE_ANY_ARG, exempt_lineno))
    if update:
        write_allowlist(ALLOW_FOR_AGENT, for_agent, 'CallerContext::for_agent("<literal>") allowlist (C8 safeguard).')
        write_allowlist(ALLOW_FOR_ADMIN, for_admin,
                        'CallerContext::for_admin("<literal>") privacy-bypass allowlist (C8 safeguard).')
        print('Allowlists regenerated:')
        print(f'  {ALLOW_FOR_AGENT}')
        print(f'  {ALLOW_FOR_ADMIN}')
        return EXIT_OK
    if not ALLOW_FOR_AGENT.is_file() or not ALLOW_FOR_ADMIN.is_file():
        print(f'ERROR: allowlist file(s) missing. Run `{SELF} --update` to seed.', file=sys.stderr)
        return EXIT_SETUP

    violations = 0
    if exempt_err:
        print(f'C8 HARD-BLOCK (#5884): {exempt_err}; the GOVERNANCE_INTERNAL site is not exempt.', file=sys.stderr)
        violations += 1
    violations += check_diff('CallerContext::for_agent', for_agent, allowlist_body(ALLOW_FOR_AGENT))
    violations += check_diff('CallerContext::for_admin', for_admin, allowlist_body(ALLOW_FOR_ADMIN))

    hits = checked_literal_hits(ROOT)
    if hits:
        print('C8 HARD-BLOCK (#3943): for_admin_checked(.., <literal bool>) in production.', file=sys.stderr)
        print('  The second argument must be threaded from the admin gate (require_admin Ok', file=sys.stderr)
        print('  arm), never a literal — a literal still compiles after the gate is removed.', file=sys.stderr)
        for hit in hits:
            print(f'    {hit}', file=sys.stderr)
        violations += 1

    # #5084 / #5241 — every SQLite write transaction must open BEGIN IMMEDIATE (WriteTxn::begin).
    # The #3623 scenario harness runs this precheck in a fixture tree (no Cargo.toml) with a
    # synthetic src/; a real checkout always has the WriteTxn home, and pinned above.
    if real_checkout:
        run = subprocess.run([sys.executable, str(WRITE_TXN_SCRIPT)], capture_output=True, text=True, check=False)
        sys.stderr.write(run.stdout + run.stderr)
        if run.returncode != 0:
            print('C8 HARD-BLOCK (#5084): a SQLite transaction opened without BEGIN IMMEDIATE.', file=sys.stderr)
            violations += 1

    if violations > 0:
        print('', file=sys.stderr)
        print(f'C8 precheck FAILED with {violations} category/categories of violation.', file=sys.stderr)
        return EXIT_VIOLATION
    print(f'C8 precheck OK (for_agent: {len(for_agent)} sites, for_admin: {len(for_admin)} sites).')
    return EXIT_OK


def gate_fails(args: Optional[List[str]] = None) -> bool:
    """Run this gate as a child; True when it exits non-zero."""
    run = subprocess.run([sys.executable, str(Path(__file__).resolve())] + (args or []),
                         capture_output=True, text=True, check=False)
    return run.returncode != 0


PROBE_1651 = '''// C8 --self-test probe (transient; created + removed by qc-codegraph-precheck.py --self-test)
pub fn probe() {
    let _ = CallerContext::for_admin(sentinels::C8_SELF_TEST_PROBE);
}
'''
PROBE_3943_POSITIVE = '''// C8 #3943 self-test probe (transient; created + removed by --self-test)
pub fn probe() {
    let ctx = crate::store::CallerContext::for_admin_checked(caller.clone(), true);
    let _ = ctx;
}
'''
PROBE_3943_THREADED = '''// C8 #3943 self-test probe (transient)
pub fn probe() {
    let (caller, is_admin) = match require_admin() {
        Ok(c) => (c, true),
        Err(resp) => return resp,
    };
    let ctx = crate::store::CallerContext::for_admin_checked(caller, is_admin);
    let _ = ctx;
}
'''
PROBE_3943_CFG_TEST = '''// C8 #3943 self-test probe (transient)
#[cfg(test)]
mod tests {
    fn cov() {
        let _ = crate::store::CallerContext::for_admin_checked("ops:admin", true);
    }
}
'''
PROBE_3943_COMMENT = '''// C8 #3943 self-test probe (transient)
// for_admin_checked(.., true) yields a bypass-visibility admin ctx; pins #1062.
pub fn probe() {}
'''


def run_self_test() -> int:
    """Prove the detectors are load-bearing (#1651, #3943), then run the #3623 harness last."""
    pin_scan_root(ROOT)
    probe_1651 = ROOT / SRC_REL / 'c8_probe_1651.rs'
    probe_3943 = ROOT / SRC_REL / 'c8_probe_3943.rs'
    try:
        probe_1651.write_text(PROBE_1651, encoding='utf-8')
        if not gate_fails():
            print('C8 SELF-TEST FAIL: sentinel-form for_admin injection was NOT detected', file=sys.stderr)
            return EXIT_VIOLATION
        print('C8 SELF-TEST PASS: sentinel-form for_admin injection HARD-BLOCKed as expected')
        probe_1651.unlink()

        probe_3943.write_text(PROBE_3943_POSITIVE, encoding='utf-8')
        if not gate_fails():
            print('C8 SELF-TEST FAIL (#3943): production for_admin_checked(.., true) was NOT detected',
                  file=sys.stderr)
            return EXIT_VIOLATION
        negatives = (
            (PROBE_3943_THREADED, 'threaded for_admin_checked(caller, is_admin) was flagged'),
            (PROBE_3943_CFG_TEST, 'a #[cfg(test)] for_admin_checked(.., true) was flagged'),
            (PROBE_3943_COMMENT, 'a COMMENT spelling for_admin_checked(.., true) was flagged'),
        )
        for text, failure in negatives:
            probe_3943.write_text(text, encoding='utf-8')
            if gate_fails():
                print(f'C8 SELF-TEST FAIL (#3943): {failure}', file=sys.stderr)
                return EXIT_VIOLATION
        probe_3943.unlink()
        print('C8 SELF-TEST PASS (#3943): production literal second-arg HARD-BLOCKed;'
              ' threaded / #[cfg(test)] / comment forms accepted')
    finally:
        for probe in (probe_1651, probe_3943):
            if probe.exists():
                probe.unlink()
    pathpin.pin_path(ROOT, 'scripts/tests/gate-production-3623.py')
    return subprocess.run([sys.executable, str(HARNESS_SCRIPT), Path(__file__).name], check=False).returncode


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description='C8 caller-context allowlist and structural-drift gate.')
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--update', action='store_true', help='regenerate the allowlists from the current state')
    mode.add_argument('--self-test', action='store_true', help='prove the detectors are load-bearing')
    args = parser.parse_args(argv)
    try:
        if args.self_test:
            return run_self_test()
        return run_check(args.update)
    except (SetupError, pathpin.PinError) as err:
        print(str(err), file=sys.stderr)
        return EXIT_SETUP


if __name__ == '__main__':
    sys.exit(main())
