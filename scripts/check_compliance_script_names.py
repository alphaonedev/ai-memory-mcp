#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Compliance-document script-name anchor gate (#6141).

The adopted certification texts under ``docs/compliance/`` are verbatim copies
of a reviewed source and cannot be edited in place, so a script rename leaves
the normative text naming a file that no longer exists (#6137 ported
``check-cert-expiry.sh`` to ``check_cert_expiry.py``; #6141).

Rule: every backticked ``check-*.sh`` / ``check_*.py`` script name in a
``docs/compliance/*.md`` file must resolve to a file under ``scripts/``,
unless BOTH hold:

1. an erratum line somewhere in ``docs/compliance/`` names it together with an
   existing successor (``scripts/<name>``). An erratum line is a single line
   containing the word "erratum", the stale name in backticks, and the
   successor in backticks. The successor must resolve inside ``scripts/``: a
   ``..`` or ``.`` component, or a symlink escaping ``scripts/``, is rejected.
2. the ``<relative-doc-path>:<stale-name>`` pair is listed in
   ``scripts/qc-allowlists/compliance-script-names-allow.txt``. The allowlist
   is a burn-down ledger of the documents that carry a historical mention
   today (a stale entry that suppresses nothing, or a malformed entry, fails).
   An erratum therefore never clears the stale name in a document written
   later.

Usage:
    python3 -I scripts/check_compliance_script_names.py [--root DIR]
    python3 -I scripts/check_compliance_script_names.py --self-test

Exit codes: 0 green, 1 violation(s) found, 2 usage error, self-test failure,
or an unreadable (non-UTF-8 / I/O error) compliance document or allowlist.
"""

import argparse
import contextlib
import io
import re
import sys
import tempfile
from pathlib import Path

TOKEN_RE = re.compile(r"`((?:scripts/)?check[-_][A-Za-z0-9_-]+\.(?:sh|py))`")
SUCCESSOR_RE = re.compile(r"`scripts/([A-Za-z0-9_./-]+\.(?:sh|py))`")
ALLOW_REL = "scripts/qc-allowlists/compliance-script-names-allow.txt"
ENTRY_RE = re.compile(r"^(docs/compliance/\S+\.md):(check[-_][A-Za-z0-9_-]+\.(?:sh|py))$")


class Unreadable(Exception):
    """A compliance document or the allowlist could not be read as UTF-8."""

    def __init__(self, path):
        super().__init__(str(path))
        self.path = path


def read_text(root, path):
    """Read ``path`` as UTF-8, mapping I/O and decode errors to Unreadable."""
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        raise Unreadable(path.relative_to(root))


def scripts_exist(root, name):
    """True when ``name`` (bare or ``scripts/``-prefixed) is a file in scripts/."""
    base = name[len("scripts/"):] if name.startswith("scripts/") else name
    return any(p.is_file() and p.name == base for p in (root / "scripts").rglob(base))


def successor_ok(root, succ):
    """True when ``scripts/<succ>`` is a file that resolves inside scripts/."""
    if any(part in ("", ".", "..") for part in succ.split("/")):
        return False
    path = root / "scripts" / succ
    try:
        if not path.is_file():
            return False
        path.resolve().relative_to((root / "scripts").resolve())
    except (OSError, ValueError):
        return False
    return True


def compliance_docs(root):
    return sorted((root / "docs" / "compliance").rglob("*.md"))


def collect_errata(root, docs):
    """Map stale bare script name -> successor path, from erratum lines."""
    errata = {}
    for doc in docs:
        for line in read_text(root, doc).splitlines():
            if "erratum" not in line.lower():
                continue
            succ = [s for s in SUCCESSOR_RE.findall(line) if successor_ok(root, s)]
            if not succ:
                continue
            for tok in TOKEN_RE.findall(line):
                base = tok[len("scripts/"):] if tok.startswith("scripts/") else tok
                if base not in succ:
                    errata[base] = succ[0]
    return errata


def load_allowlist(root):
    """Return (set of (doc, stale-name) pairs, list of malformed-line problems)."""
    path = root / ALLOW_REL
    if not path.is_file():
        return set(), []
    pairs, problems = set(), []
    for lineno, raw in enumerate(read_text(root, path).splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = ENTRY_RE.match(line)
        if not m:
            problems.append("%s:%d: malformed allowlist entry %r" % (ALLOW_REL, lineno, line))
            continue
        pairs.add((m.group(1), m.group(2)))
    return pairs, problems


def check(root):
    """Return a list of violation strings for the tree at ``root``."""
    docs = compliance_docs(root)
    errata = collect_errata(root, docs)
    allowed, problems = load_allowlist(root)
    used = set()
    for doc in docs:
        rel = doc.relative_to(root).as_posix()
        for lineno, line in enumerate(read_text(root, doc).splitlines(), 1):
            for tok in TOKEN_RE.findall(line):
                if scripts_exist(root, tok):
                    continue
                base = tok[len("scripts/"):] if tok.startswith("scripts/") else tok
                if base in errata and (rel, base) in allowed:
                    used.add((rel, base))
                    continue
                problems.append(
                    "%s:%d: `%s` does not exist under scripts/ and no erratum-covered allowlist"
                    " entry (%s) names it" % (rel, lineno, tok, ALLOW_REL)
                )
    for rel, base in sorted(allowed - used):
        problems.append("%s: stale allowlist entry %s:%s suppresses nothing" % (ALLOW_REL, rel, base))
    return problems


def run_main(root):
    """Run main() against ``root``; return (exit code or 'traceback', stderr)."""
    err = io.StringIO()
    try:
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            rc = main(["--root", str(root)])
    except Exception as exc:  # a traceback is itself the failure being probed
        return "traceback:" + type(exc).__name__, err.getvalue()
    return rc, err.getvalue()


def self_test():
    scratch = Path(__file__).resolve().parent.parent / ".local-runs"
    scratch.mkdir(exist_ok=True)
    fails = []

    def expect(cond, msg):
        if not cond:
            fails.append(msg)

    with tempfile.TemporaryDirectory(dir=str(scratch)) as d:
        root = Path(d)
        (root / "scripts" / "qc-allowlists").mkdir(parents=True)
        (root / "docs" / "compliance").mkdir(parents=True)
        (root / "scripts" / "check_new.py").write_text("")
        (root / "outside.py").write_text("not a script under scripts/\n")
        allow = root / ALLOW_REL
        doc = root / "docs" / "compliance" / "A.md"
        other = root / "docs" / "compliance" / "B.md"
        erratum = "Erratum: `check-old.sh` is `scripts/check_new.py`.\n"

        allow.write_text("")
        doc.write_text("N30 enforcer is `check-old.sh`.\n")
        expect(check(root), "stale name without erratum was accepted")

        allow.write_text("docs/compliance/A.md:check-old.sh\n")
        doc.write_text("N30 enforcer is `check-old.sh`.\n" + erratum)
        expect(not check(root), "allowlisted stale name with erratum was rejected")

        # S-F3: an erratum must not clear the stale name in a doc that is not allowlisted.
        other.write_text("New text cites `check-old.sh` as the enforcer.\n")
        expect(check(root), "new doc citing the stale name was accepted despite an erratum")
        other.unlink()

        # S-F3: an allowlist entry that suppresses nothing is a violation (burn-down ledger).
        allow.write_text("docs/compliance/A.md:check-old.sh\ndocs/compliance/A.md:check-gone.sh\n")
        expect(check(root), "stale allowlist entry was accepted")
        allow.write_text("docs/compliance/A.md:check-old.sh\nnot-an-entry\n")
        expect(check(root), "malformed allowlist entry was accepted")
        allow.write_text("docs/compliance/A.md:check-old.sh\n")

        # R2-F2: a repeated <doc>:<name> line is a violation naming the duplicate.
        allow.write_text("docs/compliance/A.md:check-old.sh\ndocs/compliance/A.md:check-old.sh\n")
        expect(
            any("duplicate allowlist entry" in p for p in check(root)),
            "duplicate allowlist entry was accepted",
        )
        allow.write_text("docs/compliance/A.md:check-old.sh\n")

        # #6170: an allowlisted doc must carry its own erratum even when another doc still does.
        both = "docs/compliance/A.md:check-old.sh%s\ndocs/compliance/B.md:check-old.sh\n"
        other.write_text(erratum)
        doc.write_text("N30 enforcer is `check-old.sh`.\n")
        allow.write_text(both % "")
        expect(check(root), "allowlisted doc whose own erratum was removed was accepted")
        # #6170: only an entry marked ':pinned' may rely on an erratum in another doc.
        allow.write_text(both % ":pinned")
        expect(not check(root), "pinned entry backed by a repository erratum was rejected")
        other.unlink()
        allow.write_text("docs/compliance/A.md:check-old.sh:pinned\n")
        expect(check(root), "pinned entry with no erratum anywhere was accepted")
        allow.write_text("docs/compliance/A.md:check-old.sh\n")

        doc.write_text("Erratum: `check-old.sh` is `scripts/check_missing.py`.\n")
        expect(check(root), "erratum naming a missing successor was accepted")

        # S-F1: the successor must resolve inside scripts/.
        doc.write_text("N30 is `check-old.sh`.\nErratum: `check-old.sh` is `scripts/../outside.py`.\n")
        expect(check(root), "erratum naming scripts/../outside.py was accepted")
        doc.write_text("N30 is `check-old.sh`.\nErratum: `check-old.sh` is `scripts/./check_new.py`.\n")
        expect(check(root), "erratum naming a dot component was accepted")
        link = root / "scripts" / "check_link.py"
        try:
            link.symlink_to(root / "outside.py")
        except OSError:
            link = None
        if link is not None:
            doc.write_text("N30 is `check-old.sh`.\nErratum: `check-old.sh` is `scripts/check_link.py`.\n")
            expect(check(root), "erratum naming an escaping symlink was accepted")
            link.unlink()

        allow.write_text("")
        doc.write_text("See `check_new.py` and `scripts/check_new.py`.\n")
        expect(not check(root), "resolving names were rejected")

        # C-F2: an unreadable doc is exit 2 with an 'unreadable' line, never a traceback.
        doc.write_bytes(b"\xff\xfe")
        rc, err = run_main(root)
        expect(rc == 2, "non-UTF-8 doc: expected exit 2, got %r" % (rc,))
        expect("A.md: unreadable" in err, "non-UTF-8 doc: missing 'unreadable' line (stderr=%r)" % err)
    return "; ".join(fails) if fails else None


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", default=str(Path(__file__).resolve().parent.parent))
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)
    if args.self_test:
        err = self_test()
        if err:
            print("SELF-TEST FAIL: " + err, file=sys.stderr)
            return 2
        print("self-test ok")
        return 0
    try:
        problems = check(Path(args.root))
    except Unreadable as exc:
        print("FAIL %s: unreadable" % exc.path, file=sys.stderr)
        return 2
    for p in problems:
        print("FAIL " + p, file=sys.stderr)
    if problems:
        return 1
    print("compliance script-name anchors ok")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
