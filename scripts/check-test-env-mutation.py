#!/usr/bin/env python3
"""#7347 gate -- INVARIANT: in an integration-test file that mutates the process environment,
every test function must hold that file's environment lock.

Why. `std::env::set_var` / `remove_var` are `unsafe` in edition 2024 because glibc `getenv` racing
`setenv`/`unsetenv` can read a freed `environ` block and die with SIGSEGV. `cargo test` runs every
test of one binary as a thread of ONE process, so a lock that only serialises the env WRITERS is
not enough: a test that never writes the environment but reads it (any `db::open`, config load,
`std::env::var`) races the writers unless it takes the same lock. That is the #7347 shape
(`federation_pending_resurrection_2529`: three locked writers, one unlocked `db::open` reader;
SIGSEGV 0.09 s after `running 4 tests`). A nextest leg runs one process per test and cannot hit it.

Rule. For every `tests/*.rs` that calls `env::set_var` or `env::remove_var`, every `#[test]` /
`#[tokio::test]` fn in that file must take a lock, or the file must declare itself process-isolated
with a comment line `// env-mutation-gate: process-isolated -- <reason>` (run only one test per
process, e.g. under nextest).

What counts as "takes a lock". A test fn passes when its attributes carry `serial`, or its body
(comments and string literals removed) contains an identifier with a `lock` word in it
(`ENV_LOCK.lock()`, `env_lock()`, `test_env_lock()`, `blocking_lock()`, `FED_ENV_LOCK`, ...), where
words split on `_` and on CamelCase (`blocking_lock` has the word `lock`; `flush_blocking`,
`block_on`, `clock` do not). Known limits, stated plainly:
  * it does NOT prove the lock is the SAME lock the writers use; a fn that locks an unrelated
    mutex passes. The check is presence, like scripts/check-test-env-lock.sh;
  * a lock taken only in a helper the test calls is not seen (the helper's name usually carries
    `lock`, which the caller then also has to spell, so the usual idioms pass);
  * a test fn inside a macro body is not seen.
The false-negative side is accepted; the false-positive side is a one-line fix in the test.

Ratchet. Existing violations live in scripts/qc-allowlists/test-env-mutation-unlocked-baseline.txt
as `<unlocked test fns> <path>`. CI fails on (a) a file not in the baseline with an unlocked test,
(b) a file whose unlocked count rose, (c) a stale entry (the count fell or the file is clean): lower
or delete the line, so the list only shrinks.

Usage:
  scripts/check-test-env-mutation.py                    # scan tests/ against the baseline
  scripts/check-test-env-mutation.py --list             # print current <count> <path> lines
  scripts/check-test-env-mutation.py --update-baseline  # rewrite the baseline (reviewable diff)
  scripts/check-test-env-mutation.py --root DIR         # scan DIR/tests, baseline under DIR
Cargo-free, stdlib python3 only. Fixtures for the tests live under .local-runs/, never /tmp.
"""
import argparse
import pathlib
import re
import sys

BASELINE_REL = "scripts/qc-allowlists/test-env-mutation-unlocked-baseline.txt"
TESTS_REL = "tests"
ISOLATED_MARKER = re.compile(r"^\s*//\s*env-mutation-gate:\s*process-isolated\b", re.M)
ENV_MUTATION = re.compile(r"\benv::(?:set_var|remove_var)\s*\(")
FN_DECL = re.compile(r"\b(?:async\s+)?fn\s+([A-Za-z_]\w*)")
TEST_ATTR = re.compile(r"#\[\s*(?:[A-Za-z_]\w*::)*(?:test|test_case|rstest)\b")
SERIAL_ATTR = re.compile(r"#\[\s*(?:[A-Za-z_]\w*::)*serial\b")
IDENT = re.compile(r"[A-Za-z_]\w*")
CHAR_LIT = re.compile(r"'(?:\\.[^']{0,8}|[^\\'])'")
HEADER = (
    "# scripts/qc-allowlists/test-env-mutation-unlocked-baseline.txt -- issue #7347 ratchet.\n"
    "#\n"
    "# Format: <unlocked test fns> <path>\n"
    "#\n"
    "# Every test fn of a tests/*.rs that mutates the process environment must hold that\n"
    "# file's env lock (see scripts/check-test-env-mutation.py). The numbers may only fall.\n"
    "# Regenerate with: scripts/check-test-env-mutation.py --update-baseline\n"
)


def scrub(src):
    """Blank comments, string and char literals (newlines kept) so braces and idents are real."""
    out = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        two = src[i:i + 2]
        if two == "//":
            j = src.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i))
            i = j
        elif two == "/*":
            depth, j = 1, i + 2
            while j < n and depth:
                if src.startswith("/*", j):
                    depth += 1
                    j += 2
                elif src.startswith("*/", j):
                    depth -= 1
                    j += 2
                else:
                    j += 1
            out.append(re.sub(r"[^\n]", " ", src[i:j]))
            i = j
        elif c == "r" and re.match(r'r#*"', src[i:i + 12]) and (i == 0 or not src[i - 1].isalnum() and src[i - 1] != "_"):
            hashes = re.match(r"r(#*)\"", src[i:]).group(1)
            end = '"' + hashes
            j = src.find(end, i + 2 + len(hashes))
            j = n if j < 0 else j + len(end)
            out.append(re.sub(r"[^\n]", " ", src[i:j]))
            i = j
        elif c == '"':
            j = i + 1
            while j < n and src[j] != '"':
                j += 2 if src[j] == "\\" else 1
            j = min(j + 1, n)
            out.append(re.sub(r"[^\n]", " ", src[i:j]))
            i = j
        elif c == "'":
            m = CHAR_LIT.match(src, i)
            if m:
                out.append(" " * (m.end() - i))
                i = m.end()
            else:
                out.append(c)
                i += 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


def match_brace(text, open_idx):
    """Index just past the `}` closing the `{` at open_idx, or len(text) if unbalanced."""
    depth = 0
    for j in range(open_idx, len(text)):
        ch = text[j]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return j + 1
    return len(text)


def has_lock_word(ident):
    """True when the identifier carries a `lock` word (snake or CamelCase), not block/clock."""
    for part in ident.split("_"):
        if not part:
            continue
        if part.lower() in ("lock", "locks", "locked"):
            return True
        # CamelCase words: EnvLock, HmacLockGuard -- split before each capital.
        words = re.findall(r"[A-Z]?[a-z0-9]+|[A-Z]+(?![a-z])", part)
        if any(w.lower() in ("lock", "locks") for w in words):
            return True
    return False


def body_takes_lock(body):
    return any(has_lock_word(m.group(0)) for m in IDENT.finditer(body))


def test_functions(scrubbed):
    """Yield (name, takes_lock) for each test fn in scrubbed source."""
    for m in FN_DECL.finditer(scrubbed):
        # Attributes: everything since the previous item boundary.
        start = max(scrubbed.rfind(";", 0, m.start()), scrubbed.rfind("}", 0, m.start()),
                    scrubbed.rfind("{", 0, m.start())) + 1
        attrs = scrubbed[start:m.start()]
        if not TEST_ATTR.search(attrs):
            continue
        brace = scrubbed.find("{", m.end())
        semi = scrubbed.find(";", m.end())
        if brace < 0 or (0 <= semi < brace):
            continue
        body = scrubbed[brace:match_brace(scrubbed, brace)]
        yield m.group(1), bool(SERIAL_ATTR.search(attrs)) or body_takes_lock(body)


def scan_file(path):
    """Return the number of unlocked test fns in an env-mutating, non-isolated file, else 0."""
    raw = path.read_text(encoding="utf-8", errors="replace")
    if ISOLATED_MARKER.search(raw):
        return 0
    scrubbed = scrub(raw)
    if not ENV_MUTATION.search(scrubbed):
        return 0
    return sum(1 for _, locked in test_functions(scrubbed) if not locked)


def scan_tree(root):
    found = {}
    tests = root / TESTS_REL
    for path in sorted(tests.glob("*.rs")):
        count = scan_file(path)
        if count:
            found[path.relative_to(root).as_posix()] = count
    return found


def read_baseline(path):
    out = {}
    if not path.exists():
        return out
    for lineno, line in enumerate(path.read_text().splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) != 2 or not parts[0].isdigit():
            raise SystemExit("%s:%d: malformed baseline line: %r" % (path, lineno, line))
        out[parts[1]] = int(parts[0])
    return out


def render(found):
    return HEADER + "".join("%d %s\n" % (found[p], p) for p in sorted(found))


def compare(found, baseline):
    """Return problem lines for new, raised and stale entries."""
    problems = []
    for path, count in sorted(found.items()):
        allowed = baseline.get(path)
        if allowed is None:
            problems.append("NEW   %s: %d test fn(s) without the env lock (not in baseline)" % (path, count))
        elif count > allowed:
            problems.append("RAISED %s: %d unlocked test fn(s), baseline allows %d" % (path, count, allowed))
    for path, allowed in sorted(baseline.items()):
        count = found.get(path, 0)
        if count < allowed:
            problems.append("STALE %s: baseline %d, now %d -- lower or delete the baseline line" % (path, allowed, count))
    return problems


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--root", default=None, help="repo root (default: the repo holding this script)")
    ap.add_argument("--list", action="store_true", help="print current <count> <path> lines")
    ap.add_argument("--update-baseline", action="store_true", help="rewrite the baseline file")
    args = ap.parse_args(argv)
    root = pathlib.Path(args.root) if args.root else pathlib.Path(__file__).resolve().parents[1]
    found = scan_tree(root)
    baseline_path = root / BASELINE_REL
    if args.list:
        sys.stdout.write("".join("%d %s\n" % (found[p], p) for p in sorted(found)))
        return 0
    if args.update_baseline:
        baseline_path.parent.mkdir(parents=True, exist_ok=True)
        baseline_path.write_text(render(found))
        print("wrote %s (%d entries)" % (BASELINE_REL, len(found)))
        return 0
    problems = compare(found, read_baseline(baseline_path))
    for line in problems:
        print(line, file=sys.stderr)
    if problems:
        print("check-test-env-mutation: FAIL (%d problem(s)); every test fn of an env-mutating "
              "tests/*.rs must hold the file's env lock (#7347)" % len(problems), file=sys.stderr)
        return 1
    print("check-test-env-mutation: ok (%d baselined file(s), unlocked fns total %d)"
          % (len(found), sum(found.values())))
    return 0


if __name__ == "__main__":
    sys.exit(main())
