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
   today (a stale entry that suppresses nothing, a duplicate entry, or a
   malformed entry fails). An erratum therefore never clears the stale name in
   a document written later.

An allowlisted pair is honoured only while the document ITSELF carries an
erratum line for that name (#6170), so deleting the erratum from one document
fails the gate even when another document still carries one. The only
exception is an entry marked ``<doc>:<name>:pinned``, honoured while an erratum
for the name exists in any ``docs/compliance/`` document. ``:pinned`` is a
closed set (#6173): ``PINNABLE_DOCS`` holds exactly the two documents that
cannot carry an erratum, ``v1.0.0-DECLARATION.md`` (SHA-256 pinned) and
``ENTERPRISE-FEDERATION-CERTIFICATION.md`` (cert section 7 gate). A ``:pinned``
entry for any other document is a violation, and so is a ``:pinned`` entry for
a document that carries its own erratum for that name ("unnecessary :pinned").

Scan set (#6169, #6197): every ``*.md`` file under ``docs/compliance/``, extension
matched in any case. A directory that cannot be listed, an unreadable document or
allowlist, or a missing ``docs/compliance/`` exits 2; nothing is skipped silently.
Symlinked directories (``docs/compliance/`` itself included) are refused, never
followed, and a document symlink that resolves outside the repository is refused;
both are violations. A document symlink inside the repository is scanned.

Usage:
    python3 -I scripts/check_compliance_script_names.py [--root DIR]
    python3 -I scripts/check_compliance_script_names.py --self-test

Exit codes: 0 green, 1 violation(s) found, 2 usage error, self-test failure,
or an unreadable (non-UTF-8 / I/O error) compliance document, directory or
allowlist.
"""

import argparse
import contextlib
import io
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

TOKEN_RE = re.compile(r"`((?:scripts/)?check[-_][A-Za-z0-9_-]+\.(?:sh|py))`")
SUCCESSOR_RE = re.compile(r"`scripts/([A-Za-z0-9_./-]+\.(?:sh|py))`")
ALLOW_REL = "scripts/qc-allowlists/compliance-script-names-allow.txt"
ENTRY_RE = re.compile(
    r"^(docs/compliance/\S+\.md):(check[-_][A-Za-z0-9_-]+\.(?:sh|py))(:pinned)?$"
)
# The two documents that cannot carry an erratum, each already guarded by another
# gate: the SHA-256 declaration pin and the cert section 7 gate (#6173).
PINNABLE_DOCS = frozenset(
    {
        "docs/compliance/v1.0.0-DECLARATION.md",
        "docs/compliance/ENTERPRISE-FEDERATION-CERTIFICATION.md",
    }
)


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


def rel_path(root, path):
    """``path`` relative to ``root`` for messages; the raw path when it is not under ``root``."""
    try:
        return Path(path).relative_to(root).as_posix()
    except ValueError:
        return str(path)


def compliance_docs(root):
    """Return (docs, problems) for the scan set: every ``*.md`` (any case) under docs/compliance/.

    The walk never skips silently (#6169, #6197). A directory that cannot be listed, or a missing
    docs/compliance/, raises Unreadable (exit 2). Symlinked directories, docs/compliance/ itself
    included, are refused and never followed: following one would scan documents outside the
    reviewed tree and admit cycles, and a git checkout of this tree contains none. A symlinked
    document is read only when it resolves inside the repository; one that leaves it is refused.
    """
    top = root / "docs" / "compliance"
    if os.path.islink(str(top)):
        return [], ["%s: symlinked directory refused (not scanned)" % rel_path(root, top)]

    def unlistable(err):
        raise Unreadable(rel_path(root, err.filename if err.filename else top))

    docs, problems = [], []
    real_root = root.resolve()
    for dirpath, dirnames, filenames in os.walk(str(top), onerror=unlistable):
        for name in dirnames:
            if os.path.islink(os.path.join(dirpath, name)):
                problems.append(
                    "%s: symlinked directory refused (not scanned)" % rel_path(root, Path(dirpath) / name)
                )
        for name in filenames:
            if not name.lower().endswith(".md"):
                continue
            path = Path(dirpath) / name
            if path.is_symlink():
                try:
                    path.resolve().relative_to(real_root)
                except (OSError, RuntimeError, ValueError):
                    problems.append(
                        "%s: document symlink resolves outside the repository (refused)" % rel_path(root, path)
                    )
                    continue
            docs.append(path)
    return sorted(docs), problems


def collect_errata(root, docs):
    """Return (all, per_doc): stale name -> successor, globally and by doc path."""
    errata, per_doc = {}, {}
    for doc in docs:
        rel = doc.relative_to(root).as_posix()
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
                    per_doc.setdefault(rel, {})[base] = succ[0]
    return errata, per_doc


def load_allowlist(root):
    """Return ({(doc, stale-name): pinned}, list of malformed/duplicate-line problems)."""
    path = root / ALLOW_REL
    try:
        present = path.is_file()
    except OSError:
        raise Unreadable(ALLOW_REL)
    if not present:
        return {}, []
    pairs, problems = {}, []
    for lineno, raw in enumerate(read_text(root, path).splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = ENTRY_RE.match(line)
        if not m:
            problems.append("%s:%d: malformed allowlist entry %r" % (ALLOW_REL, lineno, line))
            continue
        key = (m.group(1), m.group(2))
        if key in pairs:
            problems.append("%s:%d: duplicate allowlist entry %s:%s" % (ALLOW_REL, lineno, key[0], key[1]))
            continue
        pairs[key] = m.group(3) is not None
        if pairs[key] and key[0] not in PINNABLE_DOCS:
            problems.append(
                "%s:%d: :pinned not permitted for %s:%s (only %s)"
                % (ALLOW_REL, lineno, key[0], key[1], ", ".join(sorted(PINNABLE_DOCS)))
            )
    return pairs, problems


def check(root):
    """Return a list of violation strings for the tree at ``root``."""
    docs, problems = compliance_docs(root)
    errata, per_doc = collect_errata(root, docs)
    allowed, ledger_problems = load_allowlist(root)
    problems.extend(ledger_problems)
    used = set()
    for doc in docs:
        rel = doc.relative_to(root).as_posix()
        for lineno, line in enumerate(read_text(root, doc).splitlines(), 1):
            for tok in TOKEN_RE.findall(line):
                if scripts_exist(root, tok):
                    continue
                base = tok[len("scripts/"):] if tok.startswith("scripts/") else tok
                pinned = allowed.get((rel, base))
                covered = base in errata if pinned else base in per_doc.get(rel, {})
                if pinned is not None and covered:
                    used.add((rel, base))
                    continue
                problems.append(
                    "%s:%d: `%s` does not exist under scripts/ and no erratum-covered allowlist"
                    " entry (%s) names it" % (rel, lineno, tok, ALLOW_REL)
                )
    for (rel, base), pinned in sorted(allowed.items()):
        if pinned and base in per_doc.get(rel, {}):
            problems.append(
                "%s: unnecessary :pinned on %s:%s (the document carries its own erratum)"
                % (ALLOW_REL, rel, base)
            )
    for rel, base in sorted(set(allowed) - used):
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

    skipped = []
    euid = getattr(os, "geteuid", lambda: "n/a")()

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
        pin = root / "docs" / "compliance" / "v1.0.0-DECLARATION.md"
        both = "docs/compliance/%s:check-old.sh%s\ndocs/compliance/B.md:check-old.sh\n"
        other.write_text(erratum)
        doc.write_text("N30 enforcer is `check-old.sh`.\n")
        allow.write_text(both % ("A.md", ""))
        expect(check(root), "allowlisted doc whose own erratum was removed was accepted")
        # #6170: only a ':pinned' entry (on a PINNABLE_DOCS document) may rely on another doc's erratum.
        doc.unlink()
        pin.write_text("N30 enforcer is `check-old.sh`.\n")
        allow.write_text(both % ("v1.0.0-DECLARATION.md", ":pinned"))
        expect(not check(root), "pinned entry backed by a repository erratum was rejected")
        other.unlink()
        allow.write_text("docs/compliance/v1.0.0-DECLARATION.md:check-old.sh:pinned\n")
        expect(check(root), "pinned entry with no erratum anywhere was accepted")
        pin.unlink()
        doc.write_text("N30 enforcer is `check-old.sh`.\n")
        allow.write_text("docs/compliance/A.md:check-old.sh\n")

        # #6173: ':pinned' is a closed set; the cells use the real pinnable document paths.
        decl = root / "docs" / "compliance" / "v1.0.0-DECLARATION.md"
        cert = root / "docs" / "compliance" / "ENTERPRISE-FEDERATION-CERTIFICATION.md"
        stale = "N30 enforcer is `check-old.sh`.\n"
        other.write_text(erratum)
        doc.write_text(stale)
        allow.write_text("docs/compliance/A.md:check-old.sh:pinned\n")
        expect(
            any(":pinned" in p and "A.md" in p for p in check(root)),
            "#6173: ':pinned' on a document outside PINNABLE_DOCS was accepted",
        )
        # S1 (security R5): PINNABLE_DOCS compares full paths, never basenames.
        (root / "docs" / "compliance" / "sub").mkdir()
        sub = root / "docs" / "compliance" / "sub" / "v1.0.0-DECLARATION.md"
        sub.write_text(stale)
        doc.write_text(stale + erratum)
        allow.write_text(
            "docs/compliance/A.md:check-old.sh\n"
            "docs/compliance/sub/v1.0.0-DECLARATION.md:check-old.sh:pinned\n"
        )
        expect(
            any(":pinned not permitted" in p for p in check(root)),
            "R6-S1: :pinned on a subfolder look-alike of a PINNABLE_DOCS basename was accepted",
        )
        sub.unlink()
        (root / "docs" / "compliance" / "sub").rmdir()
        doc.write_text(stale + erratum)
        decl.write_text(stale + erratum)
        allow.write_text("docs/compliance/v1.0.0-DECLARATION.md:check-old.sh:pinned\n")
        expect(
            any("unnecessary :pinned" in p for p in check(root)),
            "#6173: ':pinned' on a document carrying its own erratum was accepted",
        )
        decl.write_text(stale)
        cert.write_text(stale)
        allow.write_text(
            "docs/compliance/A.md:check-old.sh\n"
            "docs/compliance/v1.0.0-DECLARATION.md:check-old.sh:pinned\n"
            "docs/compliance/ENTERPRISE-FEDERATION-CERTIFICATION.md:check-old.sh:pinned\n"
        )
        other.unlink()
        doc.write_text(stale + erratum)
        expect(not check(root), "#6173: the two real pinned documents were rejected")
        decl.unlink()
        cert.unlink()
        doc.write_text("N30 enforcer is `check-old.sh`.\n")
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

        # #6141 round 5: pin the exact token, entry, erratum and allowlist semantics.
        stale = "N30 enforcer is `%s`.\n"
        # M7: an allowlist entry must match to end of line (no trailing garbage).
        doc.write_text(stale % "check-old.sh" + erratum)
        for tail in (":pinnedx", ":bogus", " trailing", "x"):
            allow.write_text("docs/compliance/A.md:check-old.sh%s\n" % tail)
            expect(
                any("malformed allowlist entry" in p for p in check(root)),
                "R5-M7: allowlist entry with trailing %r was accepted" % tail,
            )
        # M9/M10: both prefixes (check-, check_) and both suffixes (.sh, .py) are tokens.
        for name in ("check-old.py", "check_old.sh", "check_old.py", "check-old.sh"):
            allow.write_text("")
            doc.write_text(stale % name)
            expect(
                any(name in p for p in check(root)),
                "R5-M9/M10: stale `%s` without erratum was accepted" % name,
            )
            allow.write_text("docs/compliance/A.md:%s\n" % name)
            doc.write_text(stale % name + "Erratum: `%s` is `scripts/check_new.py`.\n" % name)
            expect(not check(root), "R5-M9/M10: allowlisted `%s` with erratum was rejected" % name)
        # M11: a successor line that does not say "erratum" is not an erratum.
        allow.write_text("docs/compliance/A.md:check-old.sh\n")
        doc.write_text(stale % "check-old.sh" + "N30 now uses `scripts/check_new.py` instead of `check-old.sh`.\n")
        expect(check(root), "R5-M11: a successor line without the word erratum was accepted")
        # S2 (security R5): a backticked scripts/-prefixed stale name is flagged.
        allow.write_text("")
        doc.write_text("N30 enforcer is `scripts/check-old.sh`.\n")
        expect(check(root), "R6-S2: stale scripts/-prefixed name was accepted")
        # S6 (security R5): the word "erratum" must be on the line naming the stale name and successor.
        allow.write_text("docs/compliance/A.md:check-old.sh\n")
        doc.write_text("Erratum (see below).\n" + stale % "check-old.sh" + "`check-old.sh` is `scripts/check_new.py`.\n")
        expect(check(root), "R6-S6: erratum word on a different line from the successor was accepted")
        # M12: an erratum alone never clears a stale name; the allowlist entry is required.
        allow.write_text("")
        doc.write_text(stale % "check-old.sh" + erratum)
        expect(check(root), "R5-M12: erratum without an allowlist entry was accepted")
        allow.write_text("docs/compliance/A.md:check-old.sh\n")
        doc.write_text("N30 enforcer is `check-old.sh`.\n")

        # R6 review: exit code, scripts/-prefixed tokens, scripts/-only resolution, ledger hygiene.
        allow.write_text("")
        doc.write_text("N30 enforcer is `check-old.sh`.\n")
        rc, err = run_main(root)
        expect(rc == 1 and "FAIL " in err, "R6-R1: violation tree: expected exit 1 with FAIL lines, got %r" % (rc,))
        doc.write_text("See `check_new.py`.\n")
        rc, _ = run_main(root)
        expect(rc == 0, "R6-R1: clean tree: expected exit 0, got %r" % (rc,))
        doc.write_text("N30 enforcer is `scripts/check-gone.sh`.\n")
        expect(any("scripts/check-gone.sh" in p for p in check(root)),
               "R6-R2: stale scripts/-prefixed name was accepted")
        (root / "check-gone.sh").write_text("")
        (root / "scripts" / "check-dir.sh").mkdir()
        doc.write_text("N30 is `check-gone.sh` and `check-dir.sh`.\n")
        probs = check(root)
        expect(any("check-gone.sh" in p for p in probs), "R6-R14: name resolving only outside scripts/ was accepted")
        expect(any("check-dir.sh" in p for p in probs), "R6-R14: name resolving to a directory was accepted")
        (root / "check-gone.sh").unlink()
        (root / "scripts" / "check-dir.sh").rmdir()
        doc.write_text("N30 enforcer is `check-old.sh`.\n" + erratum)
        allow.write_text("docs/compliance/A.md:check-old.sh\njunk # note\n")
        expect(any("malformed allowlist entry" in p for p in check(root)),
               "R6-R18: malformed line containing '#' was accepted")
        allow.write_text("  docs/compliance/A.md:check-old.sh  \n")
        expect(not check(root), "R6-R9: whitespace-padded allowlist entry was rejected")
        allow.write_text("")
        doc.write_text("See `check_new.py` and `scripts/check_new.py`.\n")
        expect(not check(root), "resolving names were rejected")

        # C-F2: an unreadable doc is exit 2 with an 'unreadable' line, never a traceback.
        doc.write_bytes(b"\xff\xfe")
        rc, err = run_main(root)
        expect(rc == 2, "non-UTF-8 doc: expected exit 2, got %r" % (rc,))
        expect("A.md: unreadable" in err, "non-UTF-8 doc: missing 'unreadable' line (stderr=%r)" % err)

        # Round 6 (#6169 #6195 #6196 #6197 #6198 #6199): each cell builds its own tree under ``root``.
        def fresh(name):
            r = root / name
            (r / "scripts" / "qc-allowlists").mkdir(parents=True)
            (r / "docs" / "compliance").mkdir(parents=True)
            (r / "scripts" / "check_new.py").write_text("")
            (r / ALLOW_REL).write_text("")
            return r

        def try_symlink(link, target, label):
            try:
                link.symlink_to(target)
            except OSError as exc:
                skipped.append("%s (symlink unsupported: %s)" % (label, exc))
                return False
            return True

        def denied_rc(target, sroot, label, needle):
            mode = target.stat().st_mode & 0o7777
            target.chmod(0)
            try:
                if os.access(str(target), os.R_OK):
                    skipped.append("%s (chmod 000 does not deny access to euid %s)" % (label, euid))
                    return
                rc, err = run_main(sroot)
            finally:
                target.chmod(mode)
            expect(
                rc == 2 and needle in err,
                "%s: expected exit 2 with %r, got %r (stderr=%r)" % (label, needle, rc, err),
            )

        stale_line = "N30 enforcer is `check-old.sh`.\n"
        # #6169: an unreadable directory, document or allowlist in the scan set exits 2, never 'ok'.
        r = fresh("u-dir")
        (r / "docs" / "compliance" / "locked").mkdir()
        (r / "docs" / "compliance" / "locked" / "X.md").write_text(stale_line)
        denied_rc(r / "docs" / "compliance" / "locked", r, "#6169-dir", "docs/compliance/locked: unreadable")
        r = fresh("u-file")
        (r / "docs" / "compliance" / "C.md").write_text(stale_line)
        denied_rc(r / "docs" / "compliance" / "C.md", r, "#6169-file", "docs/compliance/C.md: unreadable")
        r = fresh("u-allow")
        denied_rc(r / "scripts" / "qc-allowlists", r, "#6169-allowlist", ALLOW_REL + ": unreadable")
        r = fresh("u-missing")
        (r / "docs" / "compliance").rmdir()
        rc, err = run_main(r)
        expect(
            rc == 2 and "docs/compliance: unreadable" in err,
            "#6169-missing: missing docs/compliance: expected exit 2, got %r (stderr=%r)" % (rc, err),
        )

        # #6197: '.MD' documents are scanned; symlinked directories and escaping document symlinks are refused.
        r = fresh("s-md")
        (r / "docs" / "compliance" / "N.MD").write_text(stale_line)
        (r / "docs" / "compliance" / "M.Md").write_text(stale_line)
        probs = check(r)
        expect(any("N.MD" in p and "check-old.sh" in p for p in probs), "#6197-MD: stale name in a .MD document was accepted")
        expect(any("M.Md" in p and "check-old.sh" in p for p in probs), "#6197-Md: stale name in a .Md document was accepted")
        r = fresh("s-link")
        (r / "elsewhere").mkdir()
        (r / "elsewhere" / "X.md").write_text(stale_line)
        if try_symlink(r / "docs" / "compliance" / "linked", r / "elsewhere", "#6197-dir"):
            expect(
                any("docs/compliance/linked" in p and "symlinked directory" in p for p in check(r)),
                "#6197-dir: a symlinked subdirectory was not refused",
            )
        r = fresh("s-top")
        (r / "docs" / "compliance").rmdir()
        (r / "real").mkdir()
        (r / "real" / "X.md").write_text(stale_line)
        if try_symlink(r / "docs" / "compliance", r / "real", "#6197-top"):
            expect(
                any("docs/compliance" in p and "symlinked directory" in p for p in check(r)),
                "#6197-top: a symlinked docs/compliance was not refused",
            )
        r = fresh("s-escape")
        (root / "ext.md").write_text("Nothing stale here.\n")
        if try_symlink(r / "docs" / "compliance" / "E.md", root / "ext.md", "#6197-escape"):
            expect(
                any("E.md" in p and "outside the repository" in p for p in check(r)),
                "#6197-escape: a document symlink leaving the repository was not refused",
            )
        r = fresh("s-inside")
        (r / "notes.md").write_text(stale_line)
        if try_symlink(r / "docs" / "compliance" / "I.md", r / "notes.md", "#6197-inside"):
            expect(
                any("I.md" in p and "check-old.sh" in p for p in check(r)),
                "#6197-inside: a document symlink inside the repository was not scanned",
            )

        # #6198: a cited name resolves only to that exact path under scripts/, contained in scripts/.
        allow.write_text("")
        (root / "scripts" / "fixtures").mkdir()
        (root / "scripts" / "fixtures" / "check-nest.sh").write_text("")
        doc.write_text("N30 enforcer is `check-nest.sh`.\n")
        expect(any("check-nest.sh" in p for p in check(root)), "#6198-nested: a nested look-alike cleared a stale name")
        if try_symlink(root / "scripts" / "check-esc.sh", root / "outside.py", "#6198-escape"):
            doc.write_text("N30 enforcer is `check-esc.sh`.\n")
            expect(any("check-esc.sh" in p for p in check(root)), "#6198-escape: a symlink escaping scripts/ cleared a stale name")
            (root / "scripts" / "check-esc.sh").unlink()
        (root / "scripts" / "sub").mkdir()
        (root / "scripts" / "sub" / "check_sub.py").write_text("")
        doc.write_text("Runs `scripts/sub/check_sub.py` and `scripts/fixtures/check-nest.sh`.\n")
        expect(not check(root), "#6198-exact: an exact scripts/<subdir>/ path was rejected")
        if try_symlink(root / "scripts" / "check-alias.sh", root / "scripts" / "check_new.py", "#6198-alias"):
            doc.write_text("N30 enforcer is `check-alias.sh`.\n")
            expect(not check(root), "#6198-alias: a symlink inside scripts/ was rejected")
            (root / "scripts" / "check-alias.sh").unlink()

        # #6195: the stale name is found anywhere on a line, after removing invisible format characters.
        hidden = {
            "soft hyphen": "N30 enforcer is `check-ol­d.sh`.\n",
            "ZWSP": "N30 enforcer is `check-​old.sh`.\n",
            "ZWNJ": "N30 enforcer is `check-old‌.sh`.\n",
            "fenced block": "Run:\n\n```\nbash check-old.sh --verify\n```\n",
            "bash scripts/": "Run `bash scripts/check-old.sh`.\n",
            "./scripts/": "Run `./scripts/check-old.sh`.\n",
            "scripts/<subdir>/": "Run `scripts/sub/check-old.sh`.\n",
            "bare prose": "The enforcer check-old.sh runs on every push.\n",
            "URL": "See https://github.com/o/r/blob/main/scripts/check-old.sh for N30.\n",
        }
        for label, text in sorted(hidden.items()):
            doc.write_text(text)
            expect(any("check-old.sh" in p for p in check(root)), "#6195-%s: stale name was accepted" % label)
        doc.write_text(
            "Run `bash scripts/check_new.py`, `./scripts/check_new.py` and check_new.py;\n"
            "see https://github.com/o/r/blob/main/scripts/check_new.py and `check_​new.py`.\n"
        )
        expect(not check(root), "#6195-resolving: resolving names in prefixed forms were rejected")

        # #6196: an erratum hidden in an HTML comment never clears a stale name.
        allow.write_text("docs/compliance/A.md:check-old.sh\n")
        for label, text in (
            ("one-line comment", stale_line + "<!-- " + erratum.strip() + " -->\n"),
            ("multi-line comment", stale_line + "<!-- header\n" + erratum + "-->\n"),
            ("comment opened earlier on the line", stale_line + "<!-- x " + erratum),
        ):
            doc.write_text(text)
            expect(check(root), "#6196-%s: an erratum inside an HTML comment was accepted" % label)
        for label, text in (
            ("after a closed comment", stale_line + "<!-- header -->\n" + erratum),
            ("after a close on the same line", stale_line + "<!-- a\nb --> " + erratum),
        ):
            doc.write_text(text)
            expect(not check(root), "#6196-%s: a visible erratum was rejected" % label)

        # #6199: a fixture setup failure exits 2 with 'SELF-TEST FAIL: fixture setup', never a traceback.
        gate_src = Path(__file__).read_text(encoding="utf-8")

        def child_self_test(name, prepare):
            c = root / name
            (c / "scripts").mkdir(parents=True)
            (c / "scripts" / "check_compliance_script_names.py").write_text(gate_src, encoding="utf-8")
            undo = prepare(c / ".local-runs")
            if undo is None:
                return None
            try:
                return subprocess.run(
                    [sys.executable, "-I", str(c / "scripts" / "check_compliance_script_names.py"), "--self-test"],
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
            finally:
                undo()

        def as_file(path):
            path.write_text("not a directory\n")
            return lambda: None

        def read_only(path):
            path.mkdir()
            path.chmod(0o555)
            if os.access(str(path), os.W_OK):
                path.chmod(0o755)
                skipped.append("#6199-readonly (chmod 555 does not deny writes to euid %s)" % euid)
                return None
            return lambda: path.chmod(0o755)

        for label, prepare in (("file", as_file), ("readonly", read_only)):
            res = child_self_test("c-" + label, prepare)
            if res is None:
                continue
            expect(
                res.returncode == 2 and "SELF-TEST FAIL: fixture setup" in res.stderr and "Traceback" not in res.stderr,
                "#6199-%s: .local-runs unusable: expected exit 2 with 'fixture setup', got %r (stderr=%r)"
                % (label, res.returncode, res.stderr[-300:]),
            )
    for note in skipped:
        print("self-test: skipped %s" % note)
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
