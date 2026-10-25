#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Doc symbol/path anchor gate (#2629, v1.0.0 CERT GATE 2), ported from the
former scripts/check-doc-symbol-anchors.sh (#8171).

Documents cite file:line anchors, path.rs::symbol qualifications and
[`sym`](../src/path.rs) links that rot silently on a rename or a module
split. Rules, all keyed on path-qualified grammar so a bare backticked
identifier in prose is never guessed at:

  PATH       a cited src/<path>.rs must exist.
  LINE       a cited src/<path>.rs:<N> must name a line the file has.
  QUAL       every identifier in src/<path>.rs::<sym> and
             src/<path>.rs::{a, B::c} must be defined in that file.
  MDLINK     [`sym`](../src/path.rs) must resolve in the file.
  LADDER_TIP a claimed migrate_vNN ladder tip must equal the tip
             scripts/check-migration-ladder.sh computes.
  FILEPATH   (#8171) every backtick-quoted path under scripts/, tests/,
             docs/, .github/ or src/ that has a file extension must exist
             at the head. A doc that cites a script that was never written
             fails here.

A line that deliberately names a path as absent (a "test ! -f" assertion,
"no longer exists", "pre-modularisation" and similar, over a three-line
window) is not a stale anchor for the src/ rules. The FILEPATH rule has its
own, narrower exemption: a "(planned)" or "(PENDING-RUN" marker on the SAME
line directly after the cited path. FILEPATH resolves a leading "../" run
against the directory of the citing doc (a citation that climbs above the
repo root counts as missing); any other ".." segment, an absolute path, and
any symlink on the path are rejected (treated as missing).
Frozen doc trees are not scanned. The burn-down allowlist
scripts/qc-allowlists/doc-symbol-anchors-allow.txt fails on a STALE entry.

Exit codes: 0 pass, 1 violations, 2 analysis-engine error (fails closed).

  scripts/check-doc-symbol-anchors.py              run the gate
  scripts/check-doc-symbol-anchors.py --self-test  plant the historical shapes
      in a throwaway tree under .local-runs/ and prove each is rejected
"""

import argparse
import glob
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve()
SCRIPTS_DIR = SCRIPT.parent
DEFAULT_ROOT = SCRIPTS_DIR.parent
ENV_ROOT = "AI_MEMORY_SYMBOL_GATE_ROOT"
ENV_FAULT = "AI_MEMORY_SYMBOL_GATE_SELFTEST_FAULT"

DEF = re.compile(
    r"\b(?:pub(?:\([^)]*\))?\s+)?(?:async\s+|unsafe\s+|extern\s+\"[^\"]*\"\s+)*"
    r"(?:fn|struct|enum|trait|type|const|static|mod|union)\s+([A-Za-z_][A-Za-z0-9_]*)")
MACRO = re.compile(r"macro_rules!\s+([A-Za-z_][A-Za-z0-9_]*)")
VARIANT = re.compile(r"^\s{4}([A-Z][A-Za-z0-9_]*)\s*[,({=]", re.M)

FROZEN = re.compile(
    r"^docs/(v0\.|internal/|audit/|rfc/|adr|BASELINE|"
    r"v1\.0\.0/perfect-endpoint-assessment/)")

PATH_RE = re.compile(r"`(?:\.\./)*(src/[A-Za-z0-9_/]+\.rs)`")
PATHLN_RE = re.compile(r"`(?:\.\./)*(src/[A-Za-z0-9_/]+\.rs):(\d+)")
QUAL_RE = re.compile(
    r"`(?:\.\./)*(src/[A-Za-z0-9_/]+\.rs)::(?:\{([^}]*)\}|([A-Za-z_][A-Za-z0-9_:]*))")
MDLINK_RE = re.compile(r"\[`([A-Za-z_][A-Za-z0-9_]*)`\]\(([^)]*src/[A-Za-z0-9_/]+\.rs)[^)]*\)")
IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
# #8171: any file-looking path in the five cited classes. The trailing
# lookahead rejects globs, placeholders and directory prefixes; src/*.rs
# paths stay with the PATH/LINE/QUAL rules above.
FILEPATH_RE = re.compile(
    r"`(/?)((?:\.\./)*)((?:scripts|tests|docs|\.github|src)/[A-Za-z0-9_./-]*"
    r"[A-Za-z0-9_-]\.[A-Za-z0-9]+)(?=[`:#\s]|$)")
LADDER_CLAIM_RE = re.compile(
    r"(?:ladder (?:ends|end) at|ladder tip(?: is)?|tip is)\s*`?"
    r"(?:[A-Za-z0-9_/.]*::)?migrate_v(\d+)", re.IGNORECASE)
SCHEMA_RE = re.compile(r"CURRENT_SCHEMA_VERSION: i(?:32|64) = ([0-9]+)")

ABSENT_ASSERTION = re.compile(
    r"test ! -f|no longer exists?|pre-?modularisation|pre-?modularization|"
    r"modularisation|modularization|monolithic|formerly|\bsplit\b|renamed to|"
    r"removed in|deleted in|STALE BASE|does not exist|(?:->|→)\s*`?src/",
    re.IGNORECASE)
# Forward marker for the FILEPATH rule only: on the SAME line, directly after
# the cited path (optionally after the closing backtick).
PLANNED_AFTER = re.compile(r"^`?\s?\((?:planned\)|PENDING-RUN\b)")
CLASS_ROOTS = ("scripts", "tests", "docs", ".github", "src")

DETAIL = {
    "PATH": "cited src/ path does not exist",
    "LINE": "file:line anchor points past end-of-file",
    "QUAL": "symbol is not defined in the file it is qualified against",
    "MDLINK": "markdown symbol link does not resolve in its target file",
    "LADDER_TIP": ("claimed ladder tip disagrees with the tip "
                   "scripts/check-migration-ladder.sh computes (left=cited, right=actual)"),
    "FILEPATH": "cited path does not exist at the head",
}


class EngineError(Exception):
    """The analysis engine failed; the gate must fail closed."""


def read_text(path, rel):
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise EngineError("cannot read %s: %s (#4507 R3-F8 fail-closed)" % (rel, exc))


def ladder_tip(root):
    """Reuse the schema-tip regex of scripts/check-migration-ladder.sh."""
    gate = root / "scripts" / "check-migration-ladder.sh"
    if not gate.is_file():
        return ""
    if "read_current_schema_version() {" not in read_text(gate, str(gate)):
        raise EngineError(
            "could not find read_current_schema_version() in scripts/check-migration-ladder.sh; "
            "update this gate in lockstep")
    pg = root / "src" / "store" / "postgres.rs"
    if not pg.is_file():
        return ""
    m = SCHEMA_RE.search(read_text(pg, "src/store/postgres.rs"))
    return m.group(1) if m else ""


def scoped_docs(root):
    docs = ["CLAUDE.md", "README.md", "ROADMAP.md", "PERFORMANCE.md"]
    docs += sorted(glob.glob(os.path.join(str(root), "docs/reference/*.md")))
    docs += sorted(glob.glob(os.path.join(str(root), "docs/*.md")))
    for sub in ("security", "compliance", "spec", "integrations", "deploy", "v1.0.0"):
        docs += sorted(glob.glob(os.path.join(str(root), "docs/%s/**/*.md" % sub), recursive=True))
    prefix = str(root).rstrip("/") + "/"
    seen = []
    for d in docs:
        rel = d[len(prefix):] if d.startswith(prefix) else d
        if FROZEN.match(rel) or rel in seen:
            continue
        if (root / rel).exists():
            seen.append(rel)
    return seen


def resolve_cited(doc, prefix, rel):
    """Join a leading ``../`` run onto the citing doc's directory.

    Returns the root-relative path, or None when the citation climbs above
    the repo root.
    """
    if not prefix:
        return rel
    base = doc.split("/")[:-1]
    for _ in range(len(prefix) // 3):
        if not base:
            return None
        base.pop()
    return "/".join(base + [rel])


def cited_file_exists(root, rel):
    """True only for a regular file strictly inside the repo root.

    A path with a ``..`` segment, an absolute path, a first component outside
    the cited classes, or any symlink along the path counts as missing
    (fails closed), so the check cannot be satisfied by a file outside the
    tree or by a link pointing out of it.
    """
    parts = rel.split("/")
    if rel.startswith("/") or ".." in parts or parts[0] not in CLASS_ROOTS:
        return False
    cur = root
    for part in parts:
        cur = cur / part
        if cur.is_symlink():
            return False
    try:
        cur.resolve().relative_to(root.resolve())
    except (ValueError, OSError):
        return False
    return cur.is_file()


def analyse(root):
    """Return a list of (rule, doc, line, token, context) tuples."""
    tip = ladder_tip(root)
    if os.environ.get(ENV_FAULT):
        raise EngineError("injected analysis-engine fault (#2713)")
    per_file = {}
    line_count = {}
    prefix = str(root).rstrip("/") + "/"
    for p in sorted(glob.glob(os.path.join(str(root), "src/**/*.rs"), recursive=True)):
        rel = p[len(prefix):]
        text = read_text(p, rel)
        line_count[rel] = text.count("\n") + 1
        names = {m.group(1) for m in DEF.finditer(text)}
        names |= {m.group(1) for m in MACRO.finditer(text)}
        names |= {m.group(1) for m in VARIANT.finditer(text)}
        names.add(os.path.splitext(os.path.basename(rel))[0])
        per_file[rel] = names
    if not per_file:
        return [("SETUP", "-", 0, "-", "src/ yielded ZERO rust files; the gate would be a no-op")]

    out = []
    for doc in scoped_docs(root):
        lines = read_text(root / doc, doc).splitlines()
        for ln, line in enumerate(lines, 1):
            ctx = line.strip()
            window = "\n".join(lines[max(0, ln - 2):ln + 1])
            absent_ok = bool(ABSENT_ASSERTION.search(window))

            for m in PATH_RE.finditer(line):
                if m.group(1) not in per_file and not absent_ok:
                    out.append(("PATH", doc, ln, m.group(1), ctx))
            for m in PATHLN_RE.finditer(line):
                f, n = m.group(1), int(m.group(2))
                if f not in per_file:
                    if not absent_ok:
                        out.append(("PATH", doc, ln, f, ctx))
                elif n > line_count[f]:
                    out.append(("LINE", doc, ln, "%s:%d" % (f, n), ctx))
            for m in QUAL_RE.finditer(line):
                f = m.group(1)
                raw = m.group(2) if m.group(2) is not None else (m.group(3) or "")
                if f not in per_file:
                    if not absent_ok:
                        out.append(("PATH", doc, ln, f, ctx))
                    continue
                for tok in raw.replace(",", " ").split():
                    tok = tok.strip().rstrip("(){}[]<>.,;")
                    if not tok:
                        continue
                    for part in tok.split("::"):
                        part = part.split("(")[0].strip()
                        if not part or not IDENT_RE.match(part):
                            continue
                        if part in per_file[f]:
                            continue
                        if part.endswith("_") and any(n.startswith(part) for n in per_file[f]):
                            continue
                        out.append(("QUAL", doc, ln, "%s::%s" % (f, part), ctx))
            for m in MDLINK_RE.finditer(line):
                sym = m.group(1)
                tgt = re.sub(r"^(\.\./)+", "", m.group(2)).split("#")[0]
                if tgt not in per_file:
                    if not absent_ok:
                        out.append(("PATH", doc, ln, tgt, ctx))
                elif sym not in per_file[tgt]:
                    out.append(("MDLINK", doc, ln, "%s::%s" % (tgt, sym), ctx))
            if tip:
                for m in LADDER_CLAIM_RE.finditer(line):
                    if m.group(1) != tip:
                        out.append(("LADDER_TIP", doc, ln,
                                    "migrate_v%s!=migrate_v%s" % (m.group(1), tip), ctx))
            for m in FILEPATH_RE.finditer(line):
                f = m.group(3)
                if f.endswith(".rs") and f.startswith("src/") and not m.group(1) \
                        and not m.group(2):
                    continue  # PATH / LINE / QUAL own src/*.rs
                if not m.group(1):
                    target = resolve_cited(doc, m.group(2), f)
                    if target is not None and cited_file_exists(root, target):
                        continue
                if PLANNED_AFTER.match(line[m.end():]):
                    continue
                out.append(("FILEPATH", doc, ln,
                            ("/" if m.group(1) else "") + m.group(2) + f, ctx))
    return out


def load_allowlist(root):
    """Return (keys, malformed_raw_lines)."""
    path = root / "scripts" / "qc-allowlists" / "doc-symbol-anchors-allow.txt"
    keys = []
    bad = []
    if not path.is_file():
        return keys, bad
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        entry = raw.split("#", 1)[0].strip()
        if not entry:
            continue
        parts = entry.split()
        if len(parts) != 2 or not re.search(r"#[0-9]+", raw):
            bad.append(raw)
            continue
        keys.append("%s|%s" % (parts[0], parts[1]))
    return keys, bad


def run_gate(root):
    check = SCRIPTS_DIR / "check-claude-md-size.py"
    ref = subprocess.run([sys.executable, str(check), str(root), "--refs-only"],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    sys.stderr.write(ref.stdout + ref.stderr)
    if ref.returncode != 0:
        sys.stderr.write("FAIL: check-doc-symbol-anchors: reference file check failed "
                         "(#4507 fail-closed)\n")
        return 1
    try:
        violations = analyse(root)
    except EngineError as exc:
        sys.stderr.write("FAIL: check-doc-symbol-anchors: analysis engine errored (%s) "
                         "- refusing to report PASS (#2713 fail-closed)\n" % exc)
        return 2
    keys, bad = load_allowlist(root)
    fails = 0
    for raw in bad:
        sys.stderr.write('FAIL: doc-symbol-anchors allowlist: malformed entry "%s"\n'
                         "       expected: <doc-file> <anchor-token> #<issue>\n" % raw)
        fails += 1
    used = set()
    for rule, doc, ln, token, ctx in violations:
        if rule == "SETUP":
            sys.stderr.write("FAIL: doc-symbol-anchors: %s\n" % ctx)
            fails += 1
            continue
        key = "%s|%s" % (doc, token)
        if key in keys:
            used.add(key)
            continue
        sys.stderr.write('FAIL: doc-symbol-anchors [%s]: %s:%s cites "%s" - %s\n'
                         % (rule, doc, ln, token, DETAIL.get(rule, "unresolved anchor")))
        sys.stderr.write("       context: %s\n" % ctx[:150])
        fails += 1
    for k in sorted(set(keys)):
        if k not in used:
            sys.stderr.write("FAIL: doc-symbol-anchors allowlist: STALE entry (suppresses "
                             "nothing) - delete it: %s\n" % k.replace("|", " "))
            fails += 1
    if fails:
        sys.stderr.write("\n❌ doc symbol/path anchor gate: %d violation(s)\n"
                         "   Repoint the anchor at HEAD, or cite the symbol without a line number.\n"
                         "   An anchor that misses is worse than no anchor (register 3.2, "
                         "C-44/C-45/C-42/C-55/C-56).\n" % fails)
        return 1
    print("✅ doc symbol/path anchor gate: PASS")
    return 0


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------
def self_test():
    fix = DEFAULT_ROOT / ".local-runs" / ("doc-symbol-anchors-selftest-%d" % os.getpid())
    shutil.rmtree(str(fix), ignore_errors=True)
    for d in ("src/mcp/tools", "src/store", "docs/reference", "scripts/qc-allowlists"):
        (fix / d).mkdir(parents=True)
    ref = fix / "docs" / "reference"
    (ref / "ARCHITECTURE_REFERENCE.md").write_text(
        "# Architecture reference (fixture)\nFixture body line.\n")
    (ref / "CODE_STYLE.md").write_text("# Code style reference (fixture)\nFixture body line.\n")
    (fix / "src/mcp/tools/recall.rs").write_text(
        "pub struct RecallTool;\npub fn decorate_memory_many(rows: &[u8]) -> usize {\n"
        "    rows.len()\n}\n")
    (fix / "src/store/postgres.rs").write_text(
        "pub const CURRENT_SCHEMA_VERSION: i64 = 88;\npub struct PostgresStore;\n"
        "fn migrate_v87() {}\nfn migrate_v88() {}\n")
    (fix / "scripts/real_tool.py").write_text("# fixture\n")
    allow = fix / "scripts/qc-allowlists/doc-symbol-anchors-allow.txt"
    readme = fix / "README.md"
    clean = (
        "See `src/mcp/tools/recall.rs::decorate_memory_many` for the decorator.\n"
        "Also `src/store/postgres.rs::{PostgresStore, migrate_v87, migrate_v88}`.\n"
        "The struct is at `src/mcp/tools/recall.rs:1`.\n"
        "Module doc: [`recall`](src/mcp/tools/recall.rs).\n"
        "Script: `scripts/real_tool.py` runs it.\n"
        "Stale-base pre-flight: `test ! -f src/handlers.rs` - the monolith no longer exists.\n")
    failures = []

    def run(extra_env=None):
        env = dict(os.environ)
        env[ENV_ROOT] = str(fix)
        env.pop(ENV_FAULT, None)
        env.update(extra_env or {})
        p = subprocess.run([sys.executable, str(SCRIPT)], env=env, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, universal_newlines=True)
        return p.returncode, p.stdout

    def expect(name, extra, want_text=None, allow_text="", must_pass=False):
        readme.write_text(clean + extra)
        allow.write_text(allow_text)
        rc, out = run()
        ok = (rc == 0) if must_pass else (rc != 0)
        if ok and want_text and want_text not in out:
            ok = False
        print("%s: self-test - %s" % ("PASS" if ok else "FAIL", name))
        if not ok:
            failures.append(name)
            print("       rc=%d\n%s" % (rc, out))

    try:
        expect("control tree (correct symbol, brace list, in-range line, module link, "
               "existing scripts/ path, absent-path assertion) PASSES", "", must_pass=True)
        expect("renamed symbol decorate_memory is REJECTED",
               "\nThe decorator is `src/mcp/tools/recall.rs::decorate_memory`.\n",
               "decorate_memory")
        expect("pre-modularisation src/ path is REJECTED",
               "\nHandlers live in `src/handlers.rs` and the loop in `src/mcp.rs`.\n")
        expect("file:line anchor past EOF is REJECTED",
               "\nSee `src/mcp/tools/recall.rs:9999`.\n", "LINE")
        expect("stale migrate_vNN citation is REJECTED",
               "\nThe ladder ends at `src/store/postgres.rs::migrate_v86`.\n")
        expect("markdown link to a renamed symbol is REJECTED",
               "\nSee [`decorate_memory`](src/mcp/tools/recall.rs).\n")
        expect("missing scripts/ path is REJECTED (#8171)",
               "\nRun `scripts/ci/check_test_env_mutation.py` first.\n", "FILEPATH")
        expect("missing tests/ path is REJECTED (#8171)",
               "\nSee `tests/no_such_test.rs`.\n", "FILEPATH")
        expect("missing .github/ path is REJECTED (#8171)",
               "\nSee `.github/workflows/no-such.yml`.\n", "FILEPATH")
        expect("missing docs/ path is REJECTED (#8171)",
               "\nSee `docs/NO_SUCH.md`.\n", "FILEPATH")
        expect("glob, placeholder and directory scripts/ citations are not guessed at",
               "\nSee `scripts/*.sh` and `scripts/<name>.py` and `scripts/ci/`.\n",
               must_pass=True)
        expect("same-line (planned) after a missing scripts/ path PASSES (#8171)",
               "\nNeeds `scripts/not_yet.py` (planned) later.\n", must_pass=True)
        expect("(planned) on the line ABOVE a missing scripts/ path is REJECTED (#8171)",
               "\nWork is (planned).\nRun `scripts/not_yet.py` now.\n", "FILEPATH")
        expect("an unrelated (planned) does not exempt a missing src/ path (#8171)",
               "\nFeature X is (planned).\nHandlers live in `src/handlers.rs`.\n")
        expect("a .. segment in a cited path is REJECTED (#8171)",
               "\nSee `scripts/../README.md`.\n", "FILEPATH")
        expect("a leading ../ from the root README (above the repo root) is REJECTED (#8171)",
               "\nSee `../scripts/real_tool.py`.\n", "FILEPATH")
        (fix / "docs").mkdir(exist_ok=True)
        docs_note = fix / "docs" / "note.md"
        docs_note.write_text("See `../scripts/real_tool.py`.\n")
        expect("a leading ../ from docs/ resolves against the citing doc and PASSES (#8171)",
               "", must_pass=True)
        docs_note.write_text("See `../../scripts/real_tool.py`.\n")
        expect("a double ../ from docs/ climbing above the root is REJECTED (#8171)",
               "", "FILEPATH")
        docs_note.unlink()
        expect("an absolute cited path is REJECTED (#8171)",
               "\nSee `/scripts/real_tool.py`.\n", "FILEPATH")
        expect("a command-form citation of a missing path is REJECTED (#8171)",
               "\nRun `scripts/no_such.py --flag` now.\n", "FILEPATH")
        expect("a command-form citation of an existing path PASSES (#8171)",
               "\nRun `scripts/real_tool.py --flag` now.\n", must_pass=True)
        expect("an allowlisted anchor PASSES",
               "\nThe decorator is `src/mcp/tools/recall.rs::decorate_memory`.\n",
               allow_text="README.md src/mcp/tools/recall.rs::decorate_memory #1\n",
               must_pass=True)
        expect("a STALE allowlist entry FAILS", "", "STALE",
               allow_text="README.md src/mcp/tools/recall.rs::decorate_memory #1\n")
        expect("a MALFORMED allowlist entry HARD-FAILS", "", allow_text="README.md\n")
        readme.write_text(clean)
        allow.write_text("")
        rc, out = run({ENV_FAULT: "1"})
        ok = rc != 0 and "gate: PASS" not in out and "analysis engine errored" in out
        print("%s: self-test #2713 - an analysis-engine error FAILS CLOSED (exit %d)"
              % ("PASS" if ok else "FAIL", rc))
        if not ok:
            failures.append("fault")
        # ---- #4507 R3-6 / R3-F8 / R3-F7: reference-file checks FAIL CLOSED ----
        def check(name, want):
            rc, out = run()
            ok = rc != 0 and want in out
            print("%s: self-test #4507 - %s" % ("PASS" if ok else "FAIL", name))
            if not ok:
                failures.append(name)
                print("       rc=%d\n%s" % (rc, out))

        for rf in ("ARCHITECTURE_REFERENCE", "CODE_STYLE"):
            target = ref / (rf + ".md")
            aside = ref / (rf + ".md.aside")
            target.rename(aside)
            check("a missing %s.md FAILS CLOSED and names the file" % rf, "docs/reference/%s.md" % rf)
            target.symlink_to(aside.name)
            check("a symlinked %s.md FAILS CLOSED" % rf, "docs/reference/%s.md" % rf)
            target.unlink()
            aside.rename(target)
        for rf in ("ARCHITECTURE_REFERENCE", "CODE_STYLE"):
            target = ref / (rf + ".md")
            saved = target.read_text()
            target.write_text("")
            check("an empty %s.md FAILS CLOSED" % rf, "%s.md is empty" % rf)
            target.write_text("# Heading only\n\n## Sub\n")
            check("a heading-only %s.md FAILS CLOSED" % rf, "%s.md has only headings" % rf)
            target.write_text(saved)
        if os.getuid() != 0:
            unreadable = fix / "src" / "store" / "unreadable_fixture.rs"
            unreadable.write_text("pub fn unreadable_fixture() {}\n")
            unreadable.chmod(0)
            try:
                check("an unreadable scanned file FAILS CLOSED", "cannot read")
            finally:
                unreadable.chmod(0o644)
                unreadable.unlink()
        (fix / "docs" / "reference").rename(fix / "docs" / "reference.aside")
        (fix / "docs" / "reference").symlink_to("reference.aside")
        check("a symlinked docs/reference FAILS CLOSED", "is a symlink")
        (fix / "docs" / "reference").unlink()
        (fix / "docs" / "reference.aside").rename(fix / "docs" / "reference")
        shutil.rmtree(str(fix / "src"))
        (fix / "src").mkdir()
        rc, _ = run()
        ok = rc != 0
        print("%s: self-test - an empty src/ tree fails CLOSED" % ("PASS" if ok else "FAIL"))
        if not ok:
            failures.append("empty-src")
    finally:
        shutil.rmtree(str(fix), ignore_errors=True)
    return 1 if failures else 0


def main():
    ap = argparse.ArgumentParser(description="Doc symbol/path anchor gate (#2629, #8171)")
    ap.add_argument("--self-test", action="store_true",
                    help="plant the historical defect shapes and prove each is rejected")
    args = ap.parse_args()
    if args.self_test:
        return self_test()
    root = Path(os.environ.get(ENV_ROOT) or DEFAULT_ROOT)
    return run_gate(root)


if __name__ == "__main__":
    sys.exit(main())
