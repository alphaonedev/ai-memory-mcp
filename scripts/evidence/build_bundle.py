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
  6. copies --sanitization (author prose, no {{placeholders}} left)
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
from run_cert import BINS, LIBS, PG_BIN, PG_LIB  # noqa: E402  (one source for the leg set)

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
# agent-scratch or tmpfs path literal (#5040); the set is unchanged from the attested generator.
HOST_PATH_PREFIXES = tuple("/" + part for part in ("mnt/", "home/", "ai-scratch", "tmp/", "var/tmp", "private/tmp"))
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


def check_run(outd):
    """Refuse unless the chain section of legs.log is green; return its COUNT_DIFF notes.

    The chain section is every line up to and including the first `CHAIN_DONE aggregate_failures=<n>` row (#5042).
    That row must say 0. Failure rows (FAIL_ROWS) are refused in the chain section and also after it, so a failing
    gates row appended to an older shared legs.log still refuses; a PASSING gates row never does.
    """
    log = outd / "legs.log"
    if not log.exists():
        raise Fatal(f"{log} missing")
    lines = read(log).splitlines()
    done = next((i for i, l in enumerate(lines) if CHAIN_DONE.match(l)), None)
    if done is None:
        raise Fatal("legs.log has no `CHAIN_DONE aggregate_failures=0` line")
    bad = [l for l in lines if any(r.search(l) for r in FAIL_ROWS)]
    if bad:
        raise Fatal("run is not green:\n  " + "\n  ".join(bad))
    if CHAIN_DONE.match(lines[done]).group(1) != "0":
        raise Fatal(f"chain is not green: {lines[done]}")
    return [l.strip() for l in lines[: done + 1] if "COUNT_DIFF" in l]


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


def leak_patterns(wt, outd):
    pats = {str(wt), str(outd), str(Path.home()), *HOST_PATH_PREFIXES}
    host = socket.gethostname()
    if host and len(host) > 3:
        pats.add(host)
    return sorted(pats, key=len, reverse=True)


def hits(text, pats):
    return [(p, l) for l in text.splitlines() for p in pats if p in l]


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
        files["bootstrap-cert-gate.log"] = bcg.replace(str(wt), "<repo-root>").encode()
        files["test-results.txt"] = test_results(outd, short, a.date).encode()
        recap_rel, shipped, recap = recapture_copy(wt, a.tip, short)
        recap_name = "recapture-posture" + Path(recap_rel).suffix
        files[recap_name] = recap.encode()
        files["SANITIZATION.md"] = san.encode()

        pats = leak_patterns(wt, outd)
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
