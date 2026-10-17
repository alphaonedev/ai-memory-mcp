#!/usr/bin/env python3
"""Measure the §7 watched federation-wire delta between the prior cert bind and a candidate cert tip.

Cargo-free and read-only. Reports, for BASE..TIP:
  * every watched path that changed (same predicate as scripts/check_cert_expiry.py is_watched_path),
    with +/- line counts and the code-line count (git diff -U0, blank and // comment lines stripped);
  * the non-merge commits that touched a watched path;
  * the AI_MEMORY_FED_* identifier set under src/ at both ends (added/removed);
  * the range size (all commits / non-merge).
"""
import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))
from run_cert import anchored  # noqa: E402  (one anchoring rule for every CERT_* path)
FED_ID = re.compile(r"AI_MEMORY_FED_[A-Z0-9_]+")
HANDLER_WATCH = ("src/handlers/federation_receive.rs", "src/handlers/federation_signing_check.rs")


def git(repo, *args):
    r = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True)
    if r.returncode != 0:
        sys.stderr.write(f"git {' '.join(args)} failed rc={r.returncode}: {r.stderr}")
        sys.exit(3)
    return r.stdout


def is_watched(p):
    return p == "src/federation" or p.startswith("src/federation/") or p in HANDLER_WATCH


def code_lines(repo, base, tip, path):
    out = git(repo, "diff", "-U0", "--no-renames", f"{base}..{tip}", "--", path)
    n = 0
    for line in out.splitlines():
        if line.startswith(("+++", "---")) or not line.startswith(("+", "-")):
            continue
        body = line[1:].strip()
        if not body or body.startswith("//"):
            continue
        n += 1
    return n


def default_repo():
    """$CERT_PREP_REPO anchored to this checkout (never the caller's cwd), else this checkout (#7421)."""
    env = os.environ.get("CERT_PREP_REPO")
    return anchored(env) if env else REPO_ROOT


def fed_ids(repo, rev):
    r = subprocess.run(["git", "-C", str(repo), "grep", "-ohE", FED_ID.pattern, rev, "--", "src/"],
                       capture_output=True, text=True)
    if r.returncode not in (0, 1):  # 1 = no match; anything else is an error, never "0 ids" (#7423)
        sys.stderr.write(f"git grep failed rc={r.returncode}: {r.stderr}")
        sys.exit(3)
    return set(FED_ID.findall(r.stdout))


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo", type=Path, default=default_repo(),
                    help="git checkout to measure (default: $CERT_PREP_REPO, else this checkout: %(default)s)")
    ap.add_argument("--base", default="385da3a054c4f82bcdfd51ec2d8f07ca4947f9a5")
    ap.add_argument("--tip", required=True)
    a = ap.parse_args()
    base = git(a.repo, "rev-parse", a.base).strip()
    tip = git(a.repo, "rev-parse", a.tip).strip()
    print(f"BASE={base}\nTIP={tip}")
    if subprocess.run(["git", "-C", str(a.repo), "merge-base", "--is-ancestor", base, tip]).returncode != 0:
        print("FAIL: base is not an ancestor of tip")
        return 2
    allc = git(a.repo, "rev-list", "--count", f"{base}..{tip}").strip()
    nonm = git(a.repo, "rev-list", "--count", "--no-merges", f"{base}..{tip}").strip()
    print(f"RANGE commits={allc} non-merge={nonm}")
    total_code = 0
    total_lines = 0
    watched = []
    for row in git(a.repo, "diff", "--numstat", "--no-renames", f"{base}..{tip}").splitlines():
        add, dele, p = row.split("\t", 2)
        if is_watched(p):
            c = code_lines(a.repo, base, tip, p)
            watched.append(p)
            total_code += c
            total_lines += int(add) + int(dele)
            print(f"WATCHED {p} +{add}/-{dele} code={c}")
    print(f"WATCHED_TOTAL files={len(watched)} lines={total_lines} code={total_code}")
    if watched:
        log = git(a.repo, "log", "--no-merges", "--format=%h %s", f"{base}..{tip}", "--", *watched)
        for l in log.splitlines():
            print(f"COMMIT {l[:140]}")
    b_ids, t_ids = fed_ids(a.repo, base), fed_ids(a.repo, tip)
    for end, rev, ids in (("base", base, b_ids), ("tip", tip, t_ids)):
        if not ids:  # the federation surface always carries identifiers: an empty set is a wrong repo, rev or path (#7443)
            sys.stderr.write(f"no AI_MEMORY_FED_* identifier under src/ at {end} {rev}: wrong repo, rev or path filter\n")
            sys.exit(3)
    print(f"FED_IDS base={len(b_ids)} tip={len(t_ids)} added={sorted(t_ids - b_ids)} removed={sorted(b_ids - t_ids)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
