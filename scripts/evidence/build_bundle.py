#!/usr/bin/env python3
"""Build the §7 cert evidence bundle docs/compliance/evidence/cert-<short>/ from a run_cert.py chain run (ai:rehearsal-f2h).

Modelled on cert-385da3a05 (commit 9f68ea41a). Steps, each fatal on failure:
  1. the run is green: OUTD/legs.log has `CHAIN_DONE aggregate_failures=0` and no failure row in the runner's row
     grammar (`  RED <name>`, `  VACUOUS ...`, `... WRONG-HEAD/DIRTY ...`, see FAIL_ROWS); a passing row whose text
     contains the word RED is not a failure row (#5042)
  2. the worktree HEAD is --tip and the bundle dir does not exist yet
  3. copies an ALLOWLIST only (never a glob): the 4 posture .out files, the exit-code transcript and the 2 peer fixtures
     from OUTD/evidence; removal-proof-full.log verbatim; bootstrap-cert-gate.log with the worktree path -> <repo-root>
  4. writes test-results.txt from the per-leg logs (the LAST `test result:` line of each)
  5. writes recapture-posture.py (else .sh): the tip's scripts/recapture-cert-3607-posture.py (else .sh) with only ROOT/OUT/FIX retargeted
  6. copies --sanitization (author prose, no {{placeholders}} left) and appends one `legs.log rule:` line naming the rule
     (CONFIG, legacy or both) that judged legs.log (#7529)
  7. leak scan: no worktree / run-dir / home / mount / scratch / tmp path and no host name in any captured file;
     recapture-posture.py (or .sh) may carry only the hits the shipped script itself carries (its *_BIN fallback lines)
  8. MANIFEST.sha256 LAST, then re-verified from disk
Nothing is staged or committed. Exit 0 only when every step passed.
"""
import argparse
import datetime
import hashlib
import os
import re
import socket
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from run_cert import BINS, LIBS, PG_BIN, PG_LIB, REPO_ROOT, run_tmpdir  # noqa: E402  (one source for the leg set)

RECAPTURE_CANDIDATES = ("scripts/recapture-cert-3607-posture.py", "scripts/recapture-cert-3607-posture.sh")
EVIDENCE_FILES = (
    "posture-bare-env.out",
    "posture-hardened-env.out",
    "posture-hardened-boot-refusal.out",
    "posture-sqlcipher-pass.out",
    "posture-legs-exit-codes.txt",
    "peer-fingerprints.txt",
    "peer-attestation.json",
)
# Host path prefixes the leak scan refuses in any captured file. Built from parts so this script itself carries no
# agent-scratch or tmpfs path literal (#5040). The attested generator's set plus the macOS and root host roots (#7415).
HOST_PATH_PREFIXES = tuple("/" + part for part in (
    "mnt/", "home/", "ai-scratch", "tmp/", "var/tmp", "private/tmp", "Users/", "Volumes/", "var/folders/", "root/"))
ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
RESULT = re.compile(r"test result: \w+\. \d+ passed; .*$")


class Fatal(Exception):
    pass


def manifest_text(files):
    """MANIFEST.sha256 body for {name: bytes}; refuses a case-colliding name set (#5037).

    Refusal rationale: f1-macos-fed, the node that must verify these bundles, has a case-insensitive filesystem by
    default. A bundle holding two names that differ only in case cannot be faithfully extracted there: one entry
    silently overwrites the other, so the MANIFEST would describe a file set that cannot exist on that node. An
    instrument whose output is attested must refuse to produce such a bundle.
    The sort key is also made total, (n.lower(), n), so ordering never depends on insertion order.
    """
    seen = {}
    for n in files:
        seen.setdefault(n.lower(), []).append(n)
    clashes = sorted(sorted(v) for v in seen.values() if len(v) > 1)
    if clashes:
        raise Fatal(f"case-colliding bundle names (cannot be extracted on a case-insensitive filesystem): {clashes}")
    return "".join(f"{hashlib.sha256(files[n]).hexdigest()}  {n}\n" for n in sorted(files, key=lambda n: (n.lower(), n)))


def git(wt, *args):
    r = subprocess.run(["git", *args], cwd=wt, capture_output=True, text=True)
    if r.returncode != 0:
        raise Fatal(f"git {' '.join(args)}: rc={r.returncode} {r.stderr.strip()}")
    return r.stdout


def read(p):
    return Path(p).read_bytes().decode("utf-8", "replace")


def last_result(path):
    hits = [m.group(0) for m in (RESULT.search(ANSI.sub("", l)) for l in read(path).splitlines()) if m]
    if not hits:
        raise Fatal(f"no `test result:` line in {path}")
    return hits[-1]


# The failure rows run_cert.py writes (Run.fail() and the notes that mirror one), in the runner's OWN row grammar
# (#5042). Every pattern is anchored to the start of the row, so a passing row whose free text merely contains RED
# (the cert-expiry self-test summary reads "... watched-path violation RED with ...") never matches, and neither
# does the `CERT-RED=0` summary.
FAIL_ROWS = tuple(re.compile(p) for p in (
    r"^\s+(RED|VACUOUS)\s+\S",  # self.fail("  RED <name>") and ("  VACUOUS <name> (0 passed)")
    r"^[A-Z]+ WRONG-HEAD/DIRTY ",  # assert_tree
    r"^RESTORE FAILED ",
    r"^BCG left \d+ tracked ",
    r"^DISK-FLOOR STOP ",
    r"^GATES (DIRTY|: HEAD\^ is not )",
    r"^\s+\S+ MISSING$",  # "  posture-legs-exit-codes.txt MISSING"
    r"^\s+header: MISSING ",
    r"^\s+removal-proof header does not name the tip$",
    r"^\s+posture copy retarget failed ",
))
CHAIN_DONE = re.compile(r"^CHAIN_DONE aggregate_failures=(\d+)\b")
SECTION_START = re.compile(r"^== CERT LEGS ")
# Strict row grammar (#7438). Every row of these shapes must parse exactly, or the run is refused: a value the gate
# cannot read as an integer is never read as green.
INT_VALUE = re.compile(r"^-?[0-9]+$")
AGG_PREFIX = re.compile(r"^(CHAIN|BATTERY|PG|RP|BCG)_DONE\b")
AGG_ROW = re.compile(r"^(CHAIN|BATTERY|PG|RP|BCG)_DONE aggregate_failures=(\S*)(?: .*)?$")
EXIT_ROW = re.compile(r"^EXIT=(\S*) leg=(\S+) aggregate_failures=(\S*)(?: .*)?$")
PLAN_ROW = re.compile(r"^PLAN leg=([a-z]+) legs=([a-z]+(?:,[a-z]+)*)$")
# The section row and the _DONE row every planned leg writes (#7437). `chain` has no section of its own.
LEG_SECTION = {"battery": "== CERT LEGS", "removal": "== removal proof", "pg": "== pg coverage",
               "bootstrap": "== bootstrap-cert-gate"}
LEG_DONE = {"battery": "BATTERY", "removal": "RP", "pg": "PG", "bootstrap": "BCG", "chain": "CHAIN"}
DONE_LEG = {v: k for k, v in LEG_DONE.items()}
SECTION_LEG = {v: k for k, v in LEG_SECTION.items()}
# What each legs.log invocation promises: equal to run_cert.PLANS minus `gates` (its rows go to gates.log); a test pins
# the two tables equal, and the PLAN row is held to this table, never trusted as declared (#7487).
PLANS = {"battery": ("battery",), "pg": ("pg",), "removal": ("removal",), "bootstrap": ("bootstrap",),
         "chain": ("battery", "removal", "pg", "bootstrap", "chain")}


def int_field(line, value):
    if not INT_VALUE.match(value):
        raise Fatal(f"malformed row (an integer was expected, found {value!r}): {line.strip()[:120]}")
    return value


def parse_rows(lines):
    """Strictly parse every EXIT= and <LEG>_DONE row; return [(index, kind, values)]. A row of those shapes that does
    not match the grammar is refused, never ignored (#7438)."""
    rows = []
    for i, l in enumerate(lines):
        if l.startswith("EXIT="):
            m = EXIT_ROW.match(l)
            if not m:
                raise Fatal(f"malformed EXIT row: {l.strip()[:120]}")
            rows.append((i, "EXIT", (int_field(l, m.group(1)), m.group(2), int_field(l, m.group(3)))))
        elif AGG_PREFIX.match(l):
            m = AGG_ROW.match(l)
            if not m:
                raise Fatal(f"malformed aggregate row: {l.strip()[:120]}")
            rows.append((i, m.group(1), (int_field(l, m.group(2)),)))
    return rows


def check_block(lines, start, rows):
    """One run_cert.py invocation (a `CONFIG ` row up to the next one): it must state its PLAN, and every planned leg
    must have its section, its _DONE row, and the invocation its one EXIT=0 row (#7437). The EXIT row is the
    invocation's last row: nothing after it is accepted, not even a passing gates row (#7527). Its sections and _DONE
    rows must be exactly the planned ones, in plan order (the runner's own order); an unplanned, unfinished,
    duplicated or out-of-order section is refused (#7527)."""
    at = f"invocation at line {start + 1}"
    plans = [(i, l) for i, l in enumerate(lines) if l.startswith("PLAN ")]
    if len(plans) != 1 or plans[0][0] != 1 or not PLAN_ROW.match(plans[0][1]):
        raise Fatal(f"{at} needs exactly one well-formed `PLAN leg=<leg> legs=<a,b>` row right after its CONFIG row, "
                    f"found {[(i, l) for i, l in plans] or 'none'}")
    leg, declared = PLAN_ROW.match(plans[0][1]).groups()
    legs = declared.split(",")
    if leg not in PLANS or tuple(legs) != PLANS[leg]:
        raise Fatal(f"{at}: PLAN `{plans[0][1]}` is not the runner's plan for `{leg}` ({','.join(PLANS.get(leg, ()))})")
    exits = [r for r in rows if r[1] == "EXIT"]
    if len(exits) != 1 or exits[0][2][1] != leg or exits[0][2][0] != "0":
        raise Fatal(f"{at} (`{leg}`) needs exactly one `EXIT=0 leg={leg}` row, found "
                    f"{[(r[2][0], r[2][1]) for r in exits] or 'none'}: the leg was killed or crashed before it finished")
    after = [l.strip()[:120] for l in lines[exits[0][0] + 1:] if l.strip()]
    if after:  # #7527: the EXIT row is the invocation's last row; anything after it is another writer's
        raise Fatal(f"{at} (`{leg}`) has rows after its EXIT row (an older or concurrent runner appended to this "
                    f"legs.log): {after[:3]}; re-run with a fresh --outd")
    for name in legs:
        sect = [i for i, l in enumerate(lines) if name in LEG_SECTION and l.startswith(LEG_SECTION[name])]
        done = [r for r in rows if r[1] == LEG_DONE[name]]
        if (name in LEG_SECTION and len(sect) != 1) or len(done) != 1 or done[0][2][0] != "0" or \
                (sect and sect[0] > done[0][0]):
            raise Fatal(f"{at}: planned leg `{name}` needs one section row and one `{LEG_DONE[name]}_DONE "
                        f"aggregate_failures=0` row after it (found {len(sect)} section / {len(done)} done); "
                        "re-run with a fresh --outd")
    # #7527: exactly the planned sections and _DONE rows, in the plan's order (the runner's own order), nothing else
    want = [(kind, name) for name in legs for kind in ("section", "done") if kind == "done" or name in LEG_SECTION]
    seen = [(i, ("section", SECTION_LEG[m.group(1)])) for i, l in enumerate(lines) if (m := ANY_SECTION.match(l))]
    seen += [(i, ("done", DONE_LEG[k])) for i, k, _v in rows if k != "EXIT"]
    got = [e for _i, e in sorted(seen)]
    if got != want:
        raise Fatal(f"{at} (`{leg}`): its sections and _DONE rows are {got}, in the runner's order they must be {want} "
                    "(an unplanned or unfinished section, or legs out of order); re-run with a fresh --outd")


# Which rule judged legs.log, recorded in the bundle's SANITIZATION.md so a reader knows how strictly the run was held (#7529).
RULE_CONFIG = "CONFIG rows: every invocation held to its PLAN, its sections, its _DONE rows and its one EXIT row"
RULE_LEGACY = "legacy (an older shared log with no per-invocation header rows): each chain section needs one green CHAIN_DONE and each leg section its own _DONE row"
RULE_MIXED = RULE_CONFIG + "; rows before the first CONFIG row held to the legacy rule"


class RunNotes(list):
    """The COUNT_DIFF notes of a green legs.log (a list, as before) plus the `rule` that judged it (#7529)."""

    def __init__(self, notes, rule):
        super().__init__(notes)
        self.rule = rule

    def __eq__(self, other):  # the rule is a label of the list, not part of its value
        return list.__eq__(self, other)

    __hash__ = None


def check_run(outd):
    """Refuse unless EVERY invocation of legs.log is green and complete; return its COUNT_DIFF notes (a RunNotes
    list whose `.rule` names the rule that judged the log: CONFIG, legacy or both, #7529).

    A log written by this runner has one `CONFIG ` row per invocation, followed by its `PLAN` row; each invocation must
    show a section row and a `<LEG>_DONE aggregate_failures=0` row for every planned leg and exactly one `EXIT=0 leg=`
    row, so a standalone removal, pg or bootstrap leg (or a chain) killed after a green chain is refused (#7437). A log
    with no `CONFIG ` row (an older shared legs.log) keeps the chain-section rule: each `== CERT LEGS` section needs
    exactly one `CHAIN_DONE aggregate_failures=0` row (#5042, #7419). Independent of both, the run is refused on a
    malformed EXIT / _DONE row (#7438), a nonzero `<LEG>_DONE` or `EXIT=` value (negative included) and any failure
    row (FAIL_ROWS), before or after the chain, so a failing gates row appended to an older shared legs.log still
    refuses. In a log with CONFIG rows nothing may follow an invocation's EXIT row, so a PASSING gates row after
    it is refused too ("has rows after its EXIT row", #7527), and each invocation's legs must be in plan order. Only
    a log with no CONFIG row (the legacy rule) accepts a passing gates row after the chain. A re-run after a failure
    must use a fresh --outd.
    """
    log = outd / "legs.log"
    if not log.exists():
        raise Fatal(f"{log} missing")
    lines = read(log).splitlines()
    rows = parse_rows(lines)
    if not any(CHAIN_DONE.match(l) for l in lines):
        raise Fatal("legs.log has no `CHAIN_DONE aggregate_failures=0` line")
    bad = [l for l in lines if any(r.search(l) for r in FAIL_ROWS)]
    for i, kind, vals in rows:
        if any(v != "0" for v in (vals if kind != "EXIT" else (vals[0], vals[2]))):
            bad.append(lines[i])
    if bad:
        raise Fatal("run is not green:\n  " + "\n  ".join(bad))
    cfg = [i for i, l in enumerate(lines) if l.startswith("CONFIG ")]
    rule = RULE_LEGACY
    if cfg:
        rule = RULE_CONFIG
        legacy = lines[: cfg[0]]  # rows an older runner wrote before the first CONFIG row (#7488)
        if legacy:
            check_legacy(legacy, 0, chain=any(SECTION_START.match(l) for l in legacy))
            rule = RULE_MIXED
        for start, end in zip(cfg, cfg[1:] + [len(lines)]):
            check_block(lines[start:end], start, [(i - start, k, v) for i, k, v in rows if start <= i < end])
    else:
        check_legacy(lines, 0, chain=True)
    last = max(i for i, l in enumerate(lines) if CHAIN_DONE.match(l))
    return RunNotes([l.strip() for l in lines[: last + 1] if "COUNT_DIFF" in l], rule)


ANY_SECTION = re.compile(r"^(== CERT LEGS|== removal proof|== pg coverage|== bootstrap-cert-gate)")
LEG_ROW = {"== removal proof": "RP", "== pg coverage": "PG", "== bootstrap-cert-gate": "BCG"}


def check_legacy(lines, offset, chain):
    """Rows with no CONFIG row in front (an older shared legs.log): each `== CERT LEGS` section needs exactly one green
    CHAIN_DONE row (#5042, #7419), and every removal / pg / bootstrap section needs its own green _DONE row before the
    next section starts, so an unfinished section is refused (#7488)."""
    if chain:
        check_sections(lines, offset)
    marks = [i for i, l in enumerate(lines) if ANY_SECTION.match(l)]
    for start, end in zip(marks, marks[1:] + [len(lines)]):
        head = ANY_SECTION.match(lines[start]).group(1)
        if head not in LEG_ROW:
            continue
        done = [l for l in lines[start:end] if re.match(rf"^{LEG_ROW[head]}_DONE aggregate_failures=0\b", l)]
        if len(done) != 1:
            raise Fatal(f"section `{head}` at line {offset + start + 1} has no `{LEG_ROW[head]}_DONE aggregate_failures=0` "
                        "row before the next section: the leg was killed or crashed (re-run with a fresh --outd)")


def check_sections(lines, offset):
    """The chain rule: each `== CERT LEGS` section (the whole file when there is none) has one green CHAIN_DONE."""
    starts = [i for i, l in enumerate(lines) if SECTION_START.match(l)] or [0]
    for start, end in zip(starts, starts[1:] + [len(lines)]):
        dones = [l for l in lines[start:end] if CHAIN_DONE.match(l)]
        if len(dones) != 1 or CHAIN_DONE.match(dones[0]).group(1) != "0":
            raise Fatal(f"chain section at line {offset + start + 1} needs exactly one `CHAIN_DONE aggregate_failures=0` row, "
                        f"found {dones or 'none'} (a crashed or killed chain; re-run with a fresh --outd)")


CONFIG_PATH = re.compile(r"(cargo_slot|slot_lock|targets|tmpdir|outd)=(.*?)(?= (?:cargo_slot|slot_lock|targets|tmpdir|outd|sources)=|$)")


def config_paths(outd):
    """Every path value of every `CONFIG ` row of legs.log: what the run really used (#7444)."""
    log = outd / "legs.log"
    found = set()
    if log.exists():
        for l in read(log).splitlines():
            if l.startswith("CONFIG "):
                found.update(v.strip() for _k, v in CONFIG_PATH.findall(l) if v.strip() not in ("", "none"))
    return sorted(found)


_NAME = r"\w\-+~@%="          # characters that continue a path component
_SOFT = r".,:;)\]'\""          # punctuation that ends a sentence or a list item, or is part of a name
# a run path ends at the end of text, a slash, whitespace, a character that is neither a name nor soft punctuation, or
# soft punctuation that is itself followed by one of the first three (#7533)
_RIGHT = r"(?=/|\s|\Z|[" + _SOFT + r"]+(?:/|\s|\Z)|[^" + _NAME + _SOFT + r"/\s])"


def path_regex(p, strict_left=True):
    """Regex for a path at a real path-component boundary on the right and, when strict_left, on the left (#7533, #7491).
    The leak scan passes strict_left=False: a path glued to a leading name character stays a leak (fail closed)."""
    return re.compile((r"(?<![\w.])" if strict_left else "") + re.escape(p) + _RIGHT)


def sanitize_paths(text, wt_forms, run_paths):
    """Replace the worktree (typed and resolved forms) with <repo-root> and every recorded run path with <run-path>,
    longest first, at a path-component boundary on both sides, so no prefix is left behind and a different path that
    only shares a prefix (/data/t,v /data/t:old /data/t.bak /data/tt) is never cut (#7444, #7491, #7533)."""
    pairs = [(p, "<repo-root>") for p in wt_forms if p] + [(p, "<run-path>") for p in run_paths if p]
    for p, rep in sorted(set(pairs), key=lambda x: len(x[0]), reverse=True):
        text = path_regex(p).sub(lambda _m, rep=rep: rep, text)
    return text


def test_results(outd, short, date):
    rows = [f"# cert-{short} §5.4(4)/(7) acceptance battery — exact test result lines ({date}, {short}, default features)",
            "# eight named integration binaries:"]
    rows += [f"{n}\t{last_result(outd / f'test-{n}.log')}" for n in BINS]
    rows.append("# three lib-slice invocations (each its OWN cargo test --lib <filter>):")
    rows += [f"{n}  {last_result(outd / ('lib-' + n.replace(':', '_') + '.log'))}" for n in LIBS]
    rows.append("# #4434 coverage leg (--features sal-postgres): the cells #4434 gated behind sal-postgres, run under that feature:")
    rows.append(f"{PG_BIN[0]} [sal-postgres]\t{last_result(outd / f'test-pg-{PG_BIN[0]}.log')}")
    rows.append(f"{PG_LIB[0]} [sal-postgres]  {last_result(outd / f'lib-pg-{PG_LIB[0]}.log')}")
    for r in rows[2:]:
        if not r.startswith("#") and (" 0 failed;" not in r or not r.split("test result: ")[1].startswith("ok.")):
            raise Fatal(f"non-green result row: {r}")
    return "\n".join(rows) + "\n"


def recapture_copy(wt, tip, short):
    """Returns (relpath, shipped source, retargeted copy). Resolves the .py first, the .sh second (#7399)."""
    rel = next((c for c in RECAPTURE_CANDIDATES
                if subprocess.run(["git", "-C", str(wt), "cat-file", "-e", f"{tip}:{c}"],
                                  capture_output=True).returncode == 0), None)
    if rel is None:
        raise Fatal(f"no recapture script at {tip}; looked for " + " then ".join(RECAPTURE_CANDIDATES)
                    + ". Check the tip is a cert chain commit that carries the posture recapture script.")
    src = git(wt, "show", f"{tip}:{rel}")
    if rel.endswith(".py"):
        subs = (
            (r"^ROOT = Path\(os\.path\.abspath\(__file__\)\)\.parent\.parent(?:  #.*)?$",
             "ROOT = Path(os.path.abspath(__file__))" + ".parent" * 5),
            (r"^OUT = ROOT / .*$", f'OUT = ROOT / "docs" / "compliance" / "evidence" / "cert-{short}"'),
            (r"^FIX = ROOT / .*$", f'FIX = ROOT / ".local-runs" / "cert-{short}-fixtures"'),
        )
    else:
        subs = (
            (r'^ROOT="\$\(cd "\$\(dirname "\$0"\)/\.\." && pwd\)"$', 'ROOT="$(cd "$(dirname "$0")/../../../.." && pwd)"'),
            (r'^OUT="\$ROOT/[^"\n]*"$', f'OUT="$ROOT/docs/compliance/evidence/cert-{short}"'),
            (r'^FIX="\$ROOT/[^"\n]*"$', f'FIX="$ROOT/.local-runs/cert-{short}-fixtures"'),
        )
    body = src
    for pat, rep in subs:
        body, n = re.subn(pat, lambda _m, rep=rep: rep, body, flags=re.M)
        if n != 1:
            raise Fatal(f"recapture retarget: pattern {pat!r} matched {n} times (want 1)")
    changed = [(x, y) for x, y in zip(src.splitlines(), body.splitlines()) if x != y]
    if len(changed) != 3 or len(src.splitlines()) != len(body.splitlines()):
        raise Fatal(f"recapture retarget changed {len(changed)} lines (want exactly 3)")
    return rel, src, body


def leak_patterns(wt, outd, unresolved=(), config=()):
    """Host strings refused in any captured file: the prefixes, the checkout, the home dir, the tmp dir the run used,
    both the resolved and the as-typed forms of --wt / --outd (#7415), and every path of the run's CONFIG rows (#7444)."""
    pats = {str(wt), str(outd), str(Path.home()), str(REPO_ROOT), str(run_tmpdir()), *HOST_PATH_PREFIXES,
            *(str(p) for p in unresolved), *(str(p) for p in config)}
    host = socket.gethostname()
    if host and len(host) > 3:
        pats.add(host)
    return sorted(pats, key=len, reverse=True)


def hits(text, pats):
    """Every (pattern, line) still present. A path pattern uses the same right boundary as sanitize_paths, so a
    different path sharing its prefix is not a leak; a host prefix, a host name and a prefix ending in a slash stay plain
    substrings, and the left side stays lenient so a glued path fails closed (#7533)."""
    rxs = {p: path_regex(p, strict_left=False) for p in pats
           if p.startswith("/") and not p.endswith("/") and p not in HOST_PATH_PREFIXES}
    return [(p, l) for l in text.splitlines() for p in pats if (rxs[p].search(l) if p in rxs else p in l)]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--tip", required=True, help="full 40-hex CERT TIP FINAL sha")
    ap.add_argument("--wt", required=True, help="cert worktree (HEAD must be --tip)")
    ap.add_argument("--outd", required=True, help="run_cert.py chain output dir")
    ap.add_argument("--sanitization", required=True, help="final SANITIZATION.md (no {{placeholders}})")
    ap.add_argument("--date", default=datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d"),
                    help="run date for the test-results header (default: today UTC)")
    a = ap.parse_args()
    os.umask(0o022)
    try:
        if not re.fullmatch(r"[0-9a-f]{40}", a.tip):
            raise Fatal("--tip must be a full 40-hex sha")
        wt, outd, short = Path(a.wt).resolve(), Path(a.outd).resolve(), a.tip[:9]
        typed = (os.path.abspath(a.wt), os.path.abspath(a.outd))
        head = git(wt, "rev-parse", "HEAD").strip()
        if head != a.tip:
            raise Fatal(f"worktree HEAD {head} != tip {a.tip}")
        diffs = check_run(outd)
        dest = wt / "docs/compliance/evidence" / f"cert-{short}"
        if dest.exists():
            raise Fatal(f"{dest} already exists; refusing to overwrite")
        san = read(a.sanitization)
        if "{{" in san or "}}" in san:
            raise Fatal(f"{a.sanitization} still has {{{{placeholders}}}}")

        files = {}
        ev = outd / "evidence"
        for f in EVIDENCE_FILES:
            if not (ev / f).is_file():
                raise Fatal(f"evidence file missing: {ev / f}")
            files[f] = (ev / f).read_bytes()
        rp = read(outd / "removal-proof-full.log")
        if not re.search(r"^overall: PASS\b", rp, re.M) or rp.count("[PROVEN]") != 15 or "CERT-RED]" in rp:
            raise Fatal("removal-proof-full.log is not overall PASS with 15 PROVEN and 0 CERT-RED")
        # #4503 header, harness line 942, kept VERBATIM (GOD 313019c5: the RUN-RECORD copies it, never retyped).
        # Exactly one, naming the tip, a clean tree and all 15 controls. Its worktree= field is the ONLY host
        # path the leak scan tolerates, and only on this exact line (disclosed in SANITIZATION.md).
        hdr_re = re.compile(r"^CERT-PROOF: tip=" + re.escape(a.tip) + r" short=" + re.escape(a.tip[:9])
                            + r" branch=\S+ worktree=" + re.escape(str(wt)) + r" dirty=0 controls=15 started=\S+$")
        # The harness prints the SAME header twice by design (check-cert-removal-proof.sh lines 978 and 996): as
        # the log's first line and directly above the `overall:` verdict. Require exactly that shape.
        lines = rp.splitlines()
        all_hdr = [l for l in lines if l.startswith("CERT-PROOF:")]
        verdict_at = [i for i, l in enumerate(lines) if l.startswith("overall:")]
        if (len(all_hdr) != 2 or len(set(all_hdr)) != 1 or not hdr_re.match(all_hdr[0])
                or lines[0] != all_hdr[0] or len(verdict_at) != 1 or lines[verdict_at[0] - 1] != all_hdr[0]):
            raise Fatal("removal-proof-full.log needs the CERT-PROOF header naming the tip, "
                        f"worktree={wt}, dirty=0, controls=15 (#4503) as its first line and again directly above "
                        f"the verdict, both identical; found: {all_hdr!r}")
        cert_proof_line = all_hdr[0]
        files["removal-proof-full.log"] = rp.encode()
        bcg = read(outd / "bootstrap-cert-gate.log")
        if "CERT-BOOTSTRAP GATE: PASS" not in bcg:
            raise Fatal("bootstrap-cert-gate.log has no `CERT-BOOTSTRAP GATE: PASS`")
        run_paths = config_paths(outd)
        files["bootstrap-cert-gate.log"] = sanitize_paths(bcg, [str(wt), typed[0]], run_paths).encode()
        files["test-results.txt"] = test_results(outd, short, a.date).encode()
        recap_rel, shipped, recap = recapture_copy(wt, a.tip, short)
        recap_name = "recapture-posture" + Path(recap_rel).suffix
        files[recap_name] = recap.encode()
        files["SANITIZATION.md"] = (san.rstrip("\n") + f"\n\nlegs.log rule: {diffs.rule}\n").encode()

        pats = leak_patterns(wt, outd, unresolved=typed, config=run_paths)
        leaks = []
        for name, data in files.items():
            h = hits(data.decode("utf-8", "replace"), pats)
            if name == recap_name:
                allowed = hits(shipped, pats)
                h = [x for x in h if x not in allowed]
            if name == "removal-proof-full.log":
                h = [(q, l) for q, l in h if not (l == cert_proof_line and q in str(wt))]
            leaks += [f"{name}: [{p}] {l.strip()[:140]}" for p, l in h]
        if leaks:
            raise Fatal("leak scan found host paths/names:\n  " + "\n  ".join(leaks))

        manifest = manifest_text(files)  # before any write: a collision must leave no partial bundle dir
        dest.mkdir(parents=True)
        for name, data in files.items():
            (dest / name).write_bytes(data)
            (dest / name).chmod(0o755 if name.endswith((".sh", ".py")) else 0o644)
        (dest / "MANIFEST.sha256").write_text(manifest)
        (dest / "MANIFEST.sha256").chmod(0o644)

        for line in (dest / "MANIFEST.sha256").read_text().splitlines():
            digest, name = line.split("  ", 1)
            if hashlib.sha256((dest / name).read_bytes()).hexdigest() != digest:
                raise Fatal(f"manifest re-verify failed for {name}")
        on_disk = sorted(p.name for p in dest.iterdir())
        if on_disk != sorted([*files, "MANIFEST.sha256"]):
            raise Fatal(f"unexpected files in bundle: {on_disk}")
        print(f"BUNDLE OK {dest} files={len(on_disk)} (manifest re-verified)")
        print(test_results(outd, short, a.date), end="")
        for d in diffs:
            print(f"NOTE {d}")
        return 0
    except (Fatal, OSError) as e:
        print(f"BUNDLE FAILED: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
