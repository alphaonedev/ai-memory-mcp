#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Behaviour test of scripts/regen-pgbouncer-pool-mode-allow.py (#4667 round-5 code review).

The regen tool writes the allowlist the claim gate trusts, so every promise in its
docstring is pinned here: it refuses without a flag, --check never writes, --accept-new without
a reason leaves the gate red, a bad --reason or reasons-file reason is refused, a forbidden line
is never written, a stale entry needs --drop-stale, a changed neighbourhood needs
--refresh-context with a --reason (written above the re-bound entry as a dated record; the
original reason is kept, also for the entry after it, and an entry is never re-bound onto
another file), a repeated unit gets one entry per occurrence, a reasons-file reason made only
of {unit} is refused, and the unread-file skip list takes --skip-reason only: --reason never
excuses a skipped file, a short --skip-reason is refused and a file whose suffix is not a declared
binary type is never written to the skip list (#5208, #5209, #5206, #5210, #5367, #5478). --set-reason re-writes the reason of
the selected entries only, keeps the others' reason, and is refused when the reason is short,
when nothing is selected, or when other changes are pending (#5091).

Each case builds a small tree in scratch (TMPDIR, else <repo>/.local-runs) holding a copy of the
repository's gate, runs the repository's regen tool against it, and checks the exit codes and
the files. --mutants then applies one source edit per promise to a scratch copy of regen and
requires the case set to fail on each (a surviving mutant fails this test).

Fixture text that names a pooler mode is stored rot13-encoded so this file is not itself a
mention for the gate.

Exit codes: 0 all cases pass (and all mutants are killed), 1 a case failed or a mutant survived.
"""
import argparse
import codecs
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Callable, Dict, List, Tuple, Union

REPO = Path(__file__).resolve().parent.parent
GATE = REPO / "scripts" / "check-pgbouncer-pool-mode-claims.py"
REGEN = REPO / "scripts" / "regen-pgbouncer-pool-mode-allow.py"
ALLOW = "scripts/qc-allowlists/pgbouncer-pool-mode-allow.txt"
UNREAD = "scripts/qc-allowlists/pgbouncer-pool-mode-unread.txt"
ENV = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")


def r13(text: str) -> str:
    return codecs.decode(text, "rot13")


GOOD = "the paragraph names the withdrawn mode only to warn readers away from it"
REREAD = "the new neighbour is plain filler text and recommends nothing to operators"
SKIP = "a gzip archive of test fixtures that holds no prose for a reader at all"
RECORD = "# context re-read on "
DOC = r13("CtObhapre cbby zbqr abgrf sbe bcrengbef ner xrcg va guvf frpgvba.\n") + "Filler one.\nFiller two.\n"
DOC2 = r13("Nabgure svyr fnlf gur ctobhapre cbby zbqr vf erivrjrq ryfrjurer.\n") + "Filler.\n"
FORBIDDEN = "Example:\n\n" + r13("cbby_zbqr = genafnpgvba\n")
FORBIDDEN_EXPORT = "Example:\n\n" + r13("rkcbeg CTOBHAPRE_CBBY_ZBQR=genafnpgvba\n")  # #5366: a shell export
BASE = {
    "infra/pgbouncer/pgbouncer.ini": "[pgbouncer]\n" + r13("cbby_zbqr = frffvba\n"),
    "docs/enterprise-deployment.md": "```ini\n" + r13("cbby_zbqr = frffvba\n") + "```\n",
    ALLOW: "",
}

Body = Union[str, bytes]


def scratch() -> Path:
    base = Path(os.environ.get("TMPDIR") or str(REPO / ".local-runs"))
    base.mkdir(parents=True, exist_ok=True)
    return base


class Tree:
    """A scratch tree with the gate in it; the regen copy and rule files live beside it, outside the scan."""

    def __init__(self, regen_src: str, files: Dict[str, Body]) -> None:
        self.holder = Path(tempfile.mkdtemp(prefix="regen-test-", dir=str(scratch())))
        self.root = self.holder / "tree"
        (self.root / "scripts").mkdir(parents=True)
        shutil.copy(str(GATE), str(self.root / "scripts" / GATE.name))
        self.regen_path = self.holder / "regen.py"
        self.regen_path.write_text(regen_src, encoding="utf-8")
        body = dict(BASE)
        body.update(files)
        for rel, text in body.items():
            self.write(rel, text)

    def write(self, rel: str, text: Body) -> None:
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(text, bytes):
            path.write_bytes(text)
        else:
            path.write_text(text, encoding="utf-8")

    def read(self, rel: str) -> str:
        return (self.root / rel).read_text(encoding="utf-8")

    def regen(self, *args: str) -> int:
        cmd = [sys.executable, "-B", str(self.regen_path), "--root", str(self.root)] + list(args)
        return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=ENV, check=False).returncode

    def gate(self) -> int:
        cmd = [sys.executable, "-B", str(self.root / "scripts" / GATE.name), "--root", str(self.root)]
        return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=ENV, check=False).returncode

    def rules(self, rules: List[Dict[str, str]]) -> str:
        path = self.holder / "rules.json"
        path.write_text(json.dumps(rules), encoding="utf-8")
        return str(path)

    def close(self) -> None:
        shutil.rmtree(str(self.holder), ignore_errors=True)


def c_stale(t: Tree) -> bool:
    t.regen("--accept-new", "--reason", GOOD)
    t.write("docs/a.md", "Nothing here now.\n")
    before = t.read(ALLOW)
    return t.regen() == 1 and t.read(ALLOW) == before and t.regen("--drop-stale") == 0 and t.gate() == 0


def c_stale_group_gone(t: Tree) -> bool:
    # #5257: when every entry of a group is dropped, its reason comment goes with it
    if t.regen("--accept-new", "--reason", GOOD) != 0:
        return False
    t.write("docs/b.md", DOC2)
    if t.regen("--accept-new", "--reason", REREAD) != 0 or t.gate() != 0:
        return False
    t.write("docs/a.md", "Nothing here now.\n")
    if t.regen("--drop-stale") != 0 or t.gate() != 0:
        return False
    text = t.read(ALLOW)
    return GOOD not in text and REREAD in text and "docs/b.md" in text


def c_refresh(t: Tree) -> bool:
    t.regen("--accept-new", "--reason", GOOD)
    t.write("docs/a.md", DOC.replace("Filler one.", "This is now recommended."))
    before = t.read(ALLOW)
    if t.gate() != 2 or t.regen() != 1 or t.read(ALLOW) != before:
        return False
    # #5208: a refresh without a written reason is a fault and writes nothing
    if t.regen("--refresh-context") != 2 or t.read(ALLOW) != before:
        return False
    return (t.regen("--refresh-context", "--reason", REREAD) == 0 and t.gate() == 0
            and GOOD in t.read(ALLOW) and RECORD in t.read(ALLOW) and REREAD in t.read(ALLOW))


TWO = (DOC2.splitlines()[0] + "\nFiller A.\n\n" + "".join("Para %d.\n\n" % i for i in range(12))
       + DOC.splitlines()[0] + "\nFiller B.\n")


def c_refresh_keeps_next(t: Tree) -> bool:
    if t.regen("--accept-new", "--reason", GOOD) != 0 or t.gate() != 0:
        return False
    t.write("docs/a.md", TWO.replace("Filler A.", "Filler A changed."))
    if t.regen("--refresh-context", "--reason", REREAD) != 0 or t.gate() != 0:
        return False
    lines = t.read(ALLOW).splitlines()
    rows = [i for i, line in enumerate(lines) if line.startswith("docs/a.md")]
    # the first entry is re-bound under its record; the second keeps GOOD directly above it
    return len(rows) == 2 and lines[rows[0] - 1].startswith(RECORD) and lines[rows[1] - 1] == "# " + GOOD


def c_refresh_mid_group(t: Tree) -> bool:
    if t.regen("--accept-new", "--reason", GOOD) != 0 or t.gate() != 0:
        return False
    t.write("docs/a.md", TWO.replace("Filler B.", "Filler B changed."))
    if t.regen("--refresh-context", "--reason", REREAD) != 0 or t.gate() != 0:
        return False
    lines = t.read(ALLOW).splitlines()
    rows = [i for i, line in enumerate(lines) if line.startswith("docs/a.md")]
    # the second entry is re-bound inside the group: its own reason is repeated above its record
    return (len(rows) == 2 and lines[rows[1] - 1].startswith(RECORD) and lines[rows[1] - 2] == "# " + GOOD
            and lines[rows[0] - 1] == "# " + GOOD)


def c_refresh_other_file(t: Tree) -> bool:
    t.regen("--accept-new", "--reason", GOOD)
    t.write("docs/a.md", DOC.replace("Filler one.", "Changed."))
    t.write("docs/b.md", DOC)
    if t.regen("--refresh-context", "--reason", REREAD) not in (0, 1):
        return False
    return t.gate() != 0 or "docs/b.md" not in t.read(ALLOW)


def c_rules_cover(t: Tree) -> bool:
    rf = t.rules([{"file": "docs/a.md", "match": "for operators", "reason": GOOD}])
    return t.regen("--accept-new", "--reasons-file", rf) == 2 and t.read(ALLOW) == ""


def c_rules_unit_only(t: Tree) -> bool:
    # #5209: the quoted unit never supplies its own reason
    rf = t.rules([{"file": "docs/a.md", "match": "for operators", "reason": "{unit}"}])
    return t.regen("--accept-new", "--reasons-file", rf) == 2 and t.read(ALLOW) == ""


def c_skip_not_reason(t: Tree) -> bool:
    # #5206: --reason, written for a line, never excuses a skipped file
    return (t.regen("--accept-new", "--reason", GOOD) == 0 and t.gate() == 2
            and GOOD not in t.read(UNREAD))


def c_skip_short(t: Tree) -> bool:
    return (t.regen("--accept-new", "--reason", GOOD, "--skip-reason", "ok fine") == 2 and t.read(ALLOW) == ""
            and not (t.root / UNREAD).exists())


FIXED = "the line describes the claim gate itself and names detection vocabulary, not a setting"


def c_set_reason(t: Tree) -> bool:
    if t.regen("--accept-new", "--reason", GOOD) != 0 or t.gate() != 0:
        return False
    if t.regen("--set-reason", FIXED, "--match", "another file") != 0 or t.gate() != 0:
        return False
    lines = t.read(ALLOW).splitlines()
    rows = [i for i, line in enumerate(lines) if line.startswith("docs/a.md")]
    # only the selected (first) entry changes reason; the second keeps GOOD; nothing is reordered
    return (len(rows) == 2 and lines[rows[0] - 1] == "# " + FIXED and lines[rows[1] - 1] == "# " + GOOD
            and "another file" in lines[rows[0]] and lines.count("# " + GOOD) == 1)


def c_set_reason_refused(t: Tree) -> bool:
    if t.regen("--accept-new", "--reason", GOOD) != 0:
        return False
    before = t.read(ALLOW)
    short = t.regen("--set-reason", "ok fine", "--match", "another file")
    unselected = t.regen("--set-reason", FIXED)
    nothing = t.regen("--set-reason", FIXED, "--match", "no such text")
    t.write("docs/a.md", TWO.replace("Filler A.", "Filler A changed."))
    pending = t.regen("--set-reason", FIXED, "--match", "another file")
    return (short, unselected, nothing, pending) == (2, 2, 2, 2) and t.read(ALLOW) == before


def c_rules_reason(t: Tree) -> bool:
    rf = t.rules([{"file": "docs/a.md", "match": "for operators", "reason": "ok fine"}])
    return t.regen("--accept-new", "--reasons-file", rf) == 2 and t.read(ALLOW) == ""


REPEATED = "Y\nY\n" + DOC.splitlines()[0] + "\nY\nY\n\nY\nY\n" + DOC.splitlines()[0] + "\nY\nY\n"
CASES: List[Tuple[str, Dict[str, Body], Callable[[Tree], bool]]] = [
    ("no flag: refuses and writes nothing", {"docs/a.md": DOC}, lambda t: t.regen() == 1 and t.read(ALLOW) == ""),
    ("--accept-new without --reason leaves the gate red", {"docs/a.md": DOC},
     lambda t: t.regen("--accept-new") == 0 and t.gate() == 2),
    ("--accept-new with a reason turns the gate green", {"docs/a.md": DOC},
     lambda t: t.regen("--accept-new", "--reason", GOOD) == 0 and t.gate() == 0),
    ("a short --reason is refused", {"docs/a.md": DOC},
     lambda t: t.regen("--accept-new", "--reason", "ok fine") == 2 and t.read(ALLOW) == ""),
    ("a forbidden line is never written", {"docs/a.md": FORBIDDEN},
     lambda t: t.regen("--accept-new", "--reason", GOOD) == 2 and t.read(ALLOW) == ""),
    ("a forbidden shell export is never written (#5366)", {"docs/a.md": FORBIDDEN_EXPORT},
     lambda t: t.regen("--accept-new", "--reason", GOOD) == 2 and t.read(ALLOW) == ""),
    ("a non-UTF-8 allowlist is a fault, not a traceback (#5369)", {"docs/a.md": DOC, ALLOW: b"# \xff\n"},
     lambda t: t.regen("--check") == 2 and t.regen("--accept-new", "--reason", GOOD) == 2),
    ("--check never writes", {"docs/a.md": DOC},
     lambda t: t.regen("--check", "--accept-new", "--reason", GOOD) == 1 and t.read(ALLOW) == ""),
    ("a stale entry is removed only with --drop-stale", {"docs/a.md": DOC}, c_stale),
    ("a dropped group takes its reason comment with it", {"docs/a.md": DOC}, c_stale_group_gone),
    ("a changed neighbourhood is re-bound only with --refresh-context, keeping the reason", {"docs/a.md": DOC}, c_refresh),
    ("a repeated unit gets one entry per occurrence", {"docs/a.md": REPEATED},
     lambda t: t.regen("--accept-new", "--reason", GOOD) == 0 and t.gate() == 0),
    ("a reasons file must cover every new unit", {"docs/a.md": DOC, "docs/b.md": DOC2}, c_rules_cover),
    ("a reasons-file reason is checked", {"docs/a.md": DOC}, c_rules_reason),
    ("the skip list takes --skip-reason", {"docs/a.md": DOC, "docs/x.gz": b"\x1f\x8b\x08\x00junk"},
     lambda t: t.regen("--accept-new", "--reason", GOOD, "--skip-reason", SKIP) == 0 and t.gate() == 0
     and SKIP in t.read(UNREAD) and GOOD not in t.read(UNREAD)),
    ("--reason never excuses a skipped file", {"docs/a.md": DOC, "docs/x.gz": b"\x1f\x8b\x08\x00junk"}, c_skip_not_reason),
    ("a short --skip-reason is refused", {"docs/a.md": DOC, "docs/x.gz": b"\x1f\x8b\x08\x00junk"}, c_skip_short),
    ("a text file is never written to the skip list (#5367)",
     {"docs/a.md": DOC, "docs/c.md": b"Notes\x00" + DOC.encode("utf-8")},
     lambda t: t.regen("--accept-new", "--reason", GOOD, "--skip-reason", SKIP) == 2 and not (t.root / UNREAD).exists()
     and t.gate() == 2),
    ("a suffix-less or template file is never written to the skip list (#5367)",
     {"docs/a.md": DOC, "infra/Dockerfile": b"Notes\x00" + DOC.encode("utf-8"), "infra/x.tpl": b"Notes\x00" + DOC.encode("utf-8")},
     lambda t: t.regen("--accept-new", "--reason", GOOD, "--skip-reason", SKIP) == 2 and not (t.root / UNREAD).exists()),
    ("a NUL-only file under a binary suffix is never written to the skip list (#5478)",
     {"docs/a.md": DOC, "infra/override.bin": b"Notes\x00" + DOC.encode("utf-8")},
     lambda t: t.regen("--accept-new", "--reason", GOOD, "--skip-reason", SKIP) == 2 and not (t.root / UNREAD).exists()
     and t.gate() == 2),
    ("a magic-number file under a text suffix is never written to the skip list (#5367)",
     {"docs/a.md": DOC, "docs/c.md": b"\x1f\x8b\x08\x00junk"},
     lambda t: t.regen("--accept-new", "--reason", GOOD, "--skip-reason", SKIP) == 2 and not (t.root / UNREAD).exists()),
    ("a reasons-file reason made only of {unit} is refused", {"docs/a.md": DOC}, c_rules_unit_only),
    ("a refresh keeps the reason of the entry after it", {"docs/a.md": TWO}, c_refresh_keeps_next),
    ("a refresh inside a group keeps the group's reason", {"docs/a.md": TWO}, c_refresh_mid_group),
    ("--set-reason re-writes only the selected entry's reason", {"docs/a.md": TWO}, c_set_reason),
    ("--set-reason is refused when short, unselected or with changes pending", {"docs/a.md": TWO}, c_set_reason_refused),
    ("--refresh-context never re-binds an entry onto another file", {"docs/a.md": DOC}, c_refresh_other_file),
]

# One source edit per promise; each must make at least one case fail.
MUTANTS: List[Tuple[str, str, str]] = [
    ("forbidden lines refused", "    if forbidden and not a.check:", "    if False:"),
    ("no stock reason", 'or reason or gate.PLACEHOLDER + " before review: say why each line below is safe"',
     'or reason or "reviewed by the regen tool: this line was accepted as it stands"'),
    ("one entry per occurrence", '            out += ["%s%s%s | ctx:%s" % (rel, gate.SEPARATOR, text, ctx)] * n',
     '            out += ["%s%s%s | ctx:%s" % (rel, gate.SEPARATOR, text, ctx)]'),
    ("--check never writes", "    if a.check or refused:", "    if refused:"),
    ("reasons file covers every unit", "        if left and a.accept_new and not a.check:", "        if False:"),
    ("stale needs --drop-stale", "    refused = ((stale or stale_unread) and not a.drop_stale) or", "    refused = False or"),
    ("refresh writes the new ctx", '                line = "%s | ctx:%s" % (body, redo[key].pop(0))', "                redo[key].pop(0)"),
    ("skip list writes its reason", '                "# " + (reason or gate.PLACEHOLDER', '                "# " + ("" or gate.PLACEHOLDER'),
    ("skip list takes --skip-reason only", "write_unread(gate, root, listed, stale_unread, new_unread, skip_reason)",
     "write_unread(gate, root, listed, stale_unread, new_unread, skip_reason or reason)"),
    ("--reason checked", 'for flag, text in (("--reason", reason), ("--skip-reason", skip_reason),',
     'for flag, text in (("--skip-reason", skip_reason),'),
    ("--skip-reason checked", '("--reason", reason), ("--skip-reason", skip_reason), ("--set-reason"',
     '("--reason", reason), ("--set-reason"'),
    ("reasons-file reason checked", "problem = gate.reason_problem(written) or gate.reason_problem(text)", "problem = None"),
    ("reasons-file {unit} not a reason", "problem = gate.reason_problem(written) or gate.reason_problem(text)",
     "problem = gate.reason_problem(text)"),
    ("refresh needs --reason", "    if refresh and a.refresh_context and not a.check and not reason:", "    if False:"),
    ("refresh writes its record",
     '                out.append("# context re-read on %s: %s" % (datetime.date.today().isoformat(), reason))\n', ""),
    ("refresh keeps the next reason", '                out.append("# " + restore)  # the entries after', '                pass  # the entries after'),
    ("skip list refuses a non-binary suffix (#5367)", "    if text_named:", "    if False:"),
    ("skip list refuses a file with no binary magic number (#5478)", "\n                  or not unreadable[rel].startswith(gate.MAGIC_REASON)]", "]"),
    ("skip list refuses a text suffix even with a magic number (#5367)", "Path(rel).suffix.lower() not in gate.BINARY_SUFFIXES\n                  or ", "False\n                  or "),
    ("allowlist decode error is a fault (#5369)", "    except (OSError, UnicodeDecodeError) as exc:  # #5369",
     "    except OSError as exc:  # #5369"),
    ("set-reason checked", '("--skip-reason", skip_reason), ("--set-reason", set_reason)):',
     '("--skip-reason", skip_reason)):'),
    ("set-reason needs a selection", "        if not (a.only or a.match):\n            print(\"regen: FAULT: --set-reason needs",
     "        if False:\n            print(\"regen: FAULT: --set-reason needs"),
    ("set-reason needs a matching tree", "        if stale or new or (set(unreadable) != set(listed)):", "        if False:"),
    ("set-reason keeps the others' reason", "                    out += [\"# \" + text] if mark else old", "                    out += [\"# \" + text] if mark else []"),
    ("set-reason writes the reason", "                    out += (head + [\"# \" + text]) if mark else comments",
     "                    out += comments if mark else comments"),
    ("refresh keeps the group reason", '                    out.append("# " + current)  # a re-bound entry', '                    pass  # a re-bound entry'),
    ("drop takes an emptied group's reason", "            del out[start:]  # every entry of this paragraph was dropped", "            pass"),
    ("refresh stays in its file", "            spare.setdefault(key[:2], []).append(key[2])", "            spare.setdefault(key[1:2], []).append(key[2])"),
    ("new entries carry ctx", '            out += ["%s%s%s | ctx:%s" % (rel, gate.SEPARATOR, text, ctx)] * n',
     '            out += ["%s%s%s" % (rel, gate.SEPARATOR, text)] * n'),
]


def run_cases(regen_src: str, verbose: bool) -> List[str]:
    failed = []
    for name, files, check in CASES:
        tree = Tree(regen_src, files)
        try:
            ok = check(tree)
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            ok = False
            name += " (%s)" % type(exc).__name__
        finally:
            tree.close()
        if not ok:
            failed.append(name)
        if verbose:
            print("regen-test %s %s" % ("ok  " if ok else "FAIL", name))
    return failed


def run_mutants(src: str) -> int:
    bad = 0
    for label, old, new in MUTANTS:
        if src.count(old) != 1:
            bad += 1
            print("regen-test FAIL mutant %-34s does not apply (text found %d times)" % (label, src.count(old)))
            continue
        failed = run_cases(src.replace(old, new), verbose=False)
        bad += 0 if failed else 1
        print("regen-test %s mutant %-34s %s" % ("ok  " if failed else "FAIL", label,
                                               ("killed by " + failed[0]) if failed else "SURVIVED"))
    return bad


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--mutants", action="store_true", help="also require every regen mutant to be killed")
    args = parser.parse_args(argv)
    src = REGEN.read_text(encoding="utf-8")
    failed = run_cases(src, verbose=True)
    bad = len(failed) + (run_mutants(src) if args.mutants else 0)
    if bad:
        print("test-regen-pool-allow: FAILED (%d)" % bad, file=sys.stderr)
        return 1
    print("test-regen-pool-allow: OK (%d cases%s)" % (len(CASES), "; %d of %d mutants killed" % (len(MUTANTS), len(MUTANTS))
                                                      if args.mutants else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
