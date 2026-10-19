#!/usr/bin/env python3
"""Measure the §7 watched federation-wire delta between the prior cert bind and a candidate cert tip.

Cargo-free and read-only. Reports, for BASE..TIP:
  * every watched path that changed (same predicate as scripts/check_cert_expiry.py is_watched_path),
    with +/- line counts and the code-line count (git diff -U0, blank and // comment lines stripped);
  * the non-merge commits that touched a watched path;
  * the AI_MEMORY_FED_* identifier set under src/ at both ends (added/removed);
  * the range size (all commits / non-merge).
"""
import sys

# #7730: isolate direct entry before any filesystem-backed import. sys and the OS
# backend are built-ins; os itself is not frozen/cached on every Python 3.9 startup.
# This cannot undo interpreter startup hooks that ran before this script began.
if __name__ == "__main__" and not sys.flags.isolated:
    __import__("posix" if "posix" in sys.builtin_module_names else "nt").execv(
        sys.executable, [sys.executable, "-I", *sys.argv])

import argparse
import importlib.util
import os
import re
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
# Load only the trusted sources; neither directory becomes an import search path.
_RUN_CERT_PATH = str(Path(__file__).resolve().with_name("run_cert.py"))
_run_cert = sys.modules.get("run_cert")
if _run_cert is not None:
    if (getattr(_run_cert, "__file__", None) != _RUN_CERT_PATH
            or getattr(getattr(_run_cert, "__spec__", None), "origin", None) != _RUN_CERT_PATH):
        raise ImportError("cached run_cert is not from the expected sibling source")
else:
    _RUN_CERT_SPEC = importlib.util.spec_from_file_location("run_cert", _RUN_CERT_PATH)
    _run_cert = importlib.util.module_from_spec(_RUN_CERT_SPEC)
    sys.modules["run_cert"] = _run_cert
    try:
        _RUN_CERT_SPEC.loader.exec_module(_run_cert)
    except BaseException:
        del sys.modules["run_cert"]
        raise
anchored = _run_cert.anchored  # one anchoring rule for every CERT_* path
_EXPIRY_PATH = str(REPO_ROOT / "scripts/check_cert_expiry.py")
_expiry = sys.modules.get("check_cert_expiry")
if _expiry is not None:
    if (getattr(_expiry, "__file__", None) != _EXPIRY_PATH
            or getattr(getattr(_expiry, "__spec__", None), "origin", None) != _EXPIRY_PATH):
        raise ImportError("cached check_cert_expiry is not from the expected sibling source")
else:
    _EXPIRY_SPEC = importlib.util.spec_from_file_location("check_cert_expiry", _EXPIRY_PATH)
    _expiry = importlib.util.module_from_spec(_EXPIRY_SPEC)
    sys.modules["check_cert_expiry"] = _expiry
    try:
        _EXPIRY_SPEC.loader.exec_module(_expiry)
    except BaseException:
        del sys.modules["check_cert_expiry"]
        raise
is_watched_path = _expiry.is_watched_path  # #7664: the gate's own predicate, not a copy
FED_ID = re.compile(r"AI_MEMORY_FED_[A-Z0-9_]+")


def run_git(repo, *args, **kw):
    """git -C <repo> with the working directory <repo>; a repo that cannot be entered is exit 3, never a traceback."""
    try:
        return subprocess.run(["git", "-C", str(repo), *args], cwd=str(repo), **kw)
    except OSError as e:
        sys.stderr.write(f"git {' '.join(args)} cannot run in {repo}: {e.strerror or e}\n")
        sys.exit(3)


def git(repo, *args):
    r = run_git(repo, *args, capture_output=True)
    if r.returncode != 0:
        sys.stderr.write(f"git {' '.join(args)} failed rc={r.returncode}: {r.stderr.decode('utf-8', 'replace')}")
        sys.exit(3)
    return r.stdout.decode("utf-8", "surrogateescape")


def numstat(repo, base, tip):
    """(added, deleted, path) for BASE..TIP from `git diff --numstat -z`: NUL-separated records, paths verbatim (a
    non-ASCII or space path is never quoted). A binary file reports `-` for both counts and is returned as None/None
    (#7664, #7669)."""
    records = git(repo, "diff", "--numstat", "-z", "--no-renames", f"{base}..{tip}").split("\0")
    rows = []
    for rec in records:
        if not rec:
            continue
        add, dele, path = rec.split("\t", 2)
        rows.append((None if add == "-" else int(add), None if dele == "-" else int(dele), path))
    return rows


def code_lines(repo, base, tip, path):
    out = git(repo, "--literal-pathspecs", "diff", "-U0", "--no-renames", f"{base}..{tip}", "--", path)
    n = 0
    in_hunk = False
    for line in out.splitlines():
        if line.startswith("diff --git "):
            in_hunk = False
        elif line.startswith("@@ "):
            in_hunk = True
        # File headers precede hunks; +++/--- inside a hunk are content (#7733).
        if not in_hunk or not line.startswith(("+", "-")):
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
    r = run_git(repo, "grep", "-ohE", FED_ID.pattern, rev, "--", "src/", capture_output=True, text=True)
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
    if run_git(a.repo, "merge-base", "--is-ancestor", base, tip).returncode != 0:
        print("FAIL: base is not an ancestor of tip")
        return 2
    allc = git(a.repo, "rev-list", "--count", f"{base}..{tip}").strip()
    nonm = git(a.repo, "rev-list", "--count", "--no-merges", f"{base}..{tip}").strip()
    print(f"RANGE commits={allc} non-merge={nonm}")
    total_code = 0
    total_lines = 0
    watched = []
    for add, dele, p in numstat(a.repo, base, tip):
        if is_watched_path(p):
            c = code_lines(a.repo, base, tip, p)
            watched.append(p)
            total_code += c
            if add is None:
                print(f"WATCHED {p} binary code={c}")
            else:
                total_lines += add + dele
                print(f"WATCHED {p} +{add}/-{dele} code={c}")
    print(f"WATCHED_TOTAL files={len(watched)} lines={total_lines} code={total_code}")
    if watched:
        log = git(a.repo, "--literal-pathspecs", "log", "--no-merges", "--format=%h %s", f"{base}..{tip}", "--", *watched)
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
