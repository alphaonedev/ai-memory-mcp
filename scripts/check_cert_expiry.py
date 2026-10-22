#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""CI gate for the enterprise-federation certification section 7 expiry trigger.

Ported from scripts/check-cert-expiry.sh (#6137, per the operator's standing
Python-not-shell rule). F7 / 2026-08-12 ratification caveat, #3556, #6137.

THE DEFECT CLASS THIS CLOSES. docs/compliance/ENTERPRISE-FEDERATION-
CERTIFICATION.md section 7 states that the certification "expires on any
change to the federation wire path (`src/federation/**`,
`src/handlers/federation_receive.rs`,
`src/handlers/federation_signing_check.rs`) or the `AI_MEMORY_FED_*`
env surface" and that any such change "requires re-running 5.4(2)-(5) and
re-issuing this document against the new SHA." Until this gate that sentence
was prose-only: a federation-wire change could merge through green CI while
the cert kept being cited (the #2444 "reports success while doing nothing"
shape applied to a certification expiry trigger).

THE RULE (TASK C, verbatim, no extra escape hatches). The change under test is
the standard PR diff (push / local: `merge-base(PR-base, HEAD)..HEAD`;
pull_request: first parent..merge commit, see RANGE RESOLUTION), NEVER a diff
against the cert's pinned SHA (unrelated later PRs must not fail forever). The gate
FAILS when that diff touches ANY of:

  * src/federation/**  (the directory itself or any path under it)
  * src/handlers/federation_receive.rs
  * src/handlers/federation_signing_check.rs
  * added / removed / renamed `AI_MEMORY_FED_[A-Z0-9_]+` identifiers anywhere
    in src/  (set-diff of identifiers at merge-base vs the judged commit)

UNLESS the same change also modifies
`docs/compliance/ENTERPRISE-FEDERATION-CERTIFICATION.md` (a re-issue or voiding
record in the same change satisfies the gate).

Failure message (required wording):
  federation-wire surface changed -> the enterprise-federation certification
  expires per its section 7 -> re-issue or void the cert doc in this same change.

RANGE RESOLUTION.
  pull_request     (#6137) The job checks out the pull_request MERGE commit
                   (GITHUB_SHA). The gate judges (B) and (C) at that merge
                   commit, never at the PR head in isolation, so a branch cut
                   before the carrier's banner fix is judged on the tree that
                   would actually merge. NO merge-base is computed on a
                   pull_request: the range starts at the merge commit's FIRST
                   PARENT. A PR's change is its effect on the merged result, so
                   (A) drift and (B) the banner flip are measured from the first
                   parent to the merge commit; base-side changes since the fork
                   point were judged when they landed on the base. (Conductor
                   decision, no vote: precedent = every other CI job tests the
                   merge ref.) The first parent must be ON the live base branch
                   (`git merge-base --is-ancestor <first parent>
                   origin/$GITHUB_BASE_REF`, the ref fetched explicitly when
                   absent), not necessarily its tip: a landing on the base
                   after the merge ref was built does not change what the PR
                   contributes. The event payload's PR_BASE_SHA, which can be
                   stale, is report-only. Fail-closed (the remedy is to push a
                   new commit or sync the branch with the base; a re-run reuses
                   the same GITHUB_SHA) when GITHUB_BASE_REF / PR_HEAD_SHA are
                   unset, a sha taken from the environment is not exactly
                   40 (or 64) hex characters, the base ref cannot be fetched, a sha does not
                   resolve, the merge commit does not have exactly two parents,
                   its second parent is not PR_HEAD_SHA, its first parent is the
                   PR head (reversed parents), or its first parent is not on the
                   live base. (#6138: first parent on the base; strictly tighter
                   than the landed gate; no vote.)
  push             github.event.before .. GITHUB_SHA. An all-zero `before`
                   (new branch / first push) is N/A-skip, never a false-fail.
  workflow_dispatch / other / empty
                   CERT_EXPIRY_BASE[/HEAD] override if set (outside CI only;
                   refused under GitHub Actions, #5970); else (local
                   convenience) merge-base with @{upstream} or
                   origin/release/v1.0.0; else N/A-skip.
  GitHub Actions   (GITHUB_ACTIONS set, #5970) the event payload range is
                   authoritative: CERT_EXPIRY_BASE / CERT_EXPIRY_HEAD set in
                   the environment are refused (rc 1), as is an empty event
                   name. Outside CI the overrides stay honoured for local use.
  Shallow checkout if merge-base fails and the repo is shallow, unshallow /
                   deepen + fetch the missing tip, then retry.

THE TWO PREDICATES #3556 ADDS (2026-09-21).
  (B) a cert-doc edit satisfies the hatch ONLY if the STATUS line or the
      Binds-to line changed between the range start (merge-base; on a
      pull_request the merge commit's first parent) and the judged commit (a
      re-issue rebinds; a voiding record flips STATUS; prose does neither).
  (C) at the judged commit, a banner that says LIVE bound to <sha> must have
      NO wire-surface drift between <sha> and that commit (paths and
      AI_MEMORY_FED_* identifiers); STATUS VOID or EXPIRED makes no live claim
      and is never failed by (C). Drift is a TREE comparison (`git diff <sha>
      <commit>`), so ancestry is not required; an unparseable banner or a
      bound SHA absent from the repository is fail-closed.

WHAT THIS DOES NOT CLAIM. A value-only edit of an existing AI_MEMORY_FED_*
identifier in a file outside the three path watches does not trip the
identifier check. This gate does not re-run 5.4(2)-(5); it only forces the
cert-doc to be touched so a human/re-issue cannot be skipped.

Usage:
  scripts/check_cert_expiry.py              # against the resolved range
  scripts/check_cert_expiry.py --self-test  # runs the external corpus (below)

External corpus and ratchet (#6357, #6445). The plant-a-violation cells and one
case per member of the cert-expiry defect class live OUTSIDE this gate, in
scripts/ci/tests/test_check_cert_expiry_corpus.py. Every case builds its own
scratch git repository, so no case can depend on another, and a crash in one is
a named failure while the rest still run. `--self-test` is a thin runner over
that corpus. scripts/qc-allowlists/cert-expiry-corpus-manifest.txt records each
case as GREEN (must pass) or RED (known gap, expectedFailure); the corpus's
ratchet test fails when a case name is deleted or a GREEN case is flipped to RED.

Exit codes: 0 clean / N/A-skip, 1 violation, 2 usage / self-test failure.
"""

import argparse
import contextlib
import errno
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

CERT_DOC = "docs/compliance/ENTERPRISE-FEDERATION-CERTIFICATION.md"
FED_ID_PATTERN = "AI_MEMORY_FED_[A-Z0-9_]+"
FED_ID_RE = re.compile(FED_ID_PATTERN)
ZERO_SHA_RE = re.compile(r"^0+$")
PREFIX = "check-cert-expiry"
# Every sha taken from the environment is exactly 40 (SHA-1) or 64 (SHA-256)
# hex chars (#6138 S-F2, R2-1), matched with `fullmatch` so a trailing newline
# or an abbreviation (which git would resolve as a ref name) is refused before
# any git call, and an option-shaped value can never reach a git argv.
ENV_SHA_RE = re.compile(r"[0-9a-fA-F]{40}(?:[0-9a-fA-F]{24})?")
# `--end-of-options` is passed ahead of positional refs. `git rev-parse`
# learned it only in git 2.30 (git RelNotes/2.30.0.txt:74-76); fetch,
# merge-base, diff, show and rev-list had it since 2.24. The floor is the
# newest of those, because the gate calls `rev-parse --verify` throughout.
MIN_GIT_VERSION = (2, 30)
REGULAR_FILE_MODES = ("100644", "100755")  # ls-tree modes read_blob accepts as a file

# POSIX [[:space:]] spelled out so a Unicode space cannot widen the match.
_S = r"[ \t\r\n\f\v]"
# The banner patterns are TOLERANT of formatting (#3556 ruling, fix 3):
# optional blockquote, one to three '#', flexible whitespace, em dash / en dash
# / hyphen, optional backticks, case-insensitive hex. They are anchored at line
# start and require the heading marker / the bold "Binds to", so the section 7
# history records that QUOTE these words in prose do not match.
STATUS_LINE_RE = re.compile(
    r"^>?" + _S + r"*#{1,3}" + _S + r"*STATUS" + _S + r"*(?:—|–|-)" + _S
    + r"*\*\*" + _S + r"*(LIVE|VOID|EXPIRED)",
    re.IGNORECASE,
)
BINDS_LINE_RE = re.compile(
    r"^>?" + _S + r"*\*\*" + _S + r"*Binds" + _S + r"+to" + _S + r"*:?" + _S
    + r"*\*\*" + _S + r"*:?" + _S + r"*`?([0-9a-fA-F]{40})`?",
    re.IGNORECASE,
)

EXPIRY_SENTENCE = (
    "federation-wire surface changed → the enterprise-federation certification "
    "expires per its §7 → re-issue or void the cert doc in this same change."
)


class GateError(Exception):
    """Evidence is missing or ambiguous: the gate fails closed."""


# ---------------------------------------------------------------------------
# git plumbing
# ---------------------------------------------------------------------------


def _git_env():
    # Resolve the requested repository, not an inherited worktree/index override.
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env["GIT_NO_REPLACE_OBJECTS"] = "1"
    return env


def run_git(repo, *args, timeout=120):
    """Run git in `repo`; returns CompletedProcess with bytes output."""
    try:
        return subprocess.run(
            ["git", "-c", "core.quotePath=false", "-C", str(repo), *args],
            capture_output=True, env=_git_env(), timeout=timeout, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GateError(f"git {args[0] if args else ''} could not complete: {exc}") from exc


def git_text(repo, *args):
    """Stdout of a git command that must succeed, as stripped text."""
    proc = run_git(repo, *args)
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", "replace").strip()
        raise GateError(f"git {args[0]} exited {proc.returncode}: {err}")
    return proc.stdout.decode("utf-8", "replace").strip()


def require_git_version(repo):
    """Fail closed unless `git rev-parse` understands `--end-of-options` (>= 2.30)."""
    text = git_text(repo, "--version")
    m = re.match(r"git version (\d+)\.(\d+)", text)
    if not m or (int(m.group(1)), int(m.group(2))) < MIN_GIT_VERSION:
        need = ".".join(str(n) for n in MIN_GIT_VERSION)
        raise GateError(f"git >= {need} is required for --end-of-options (got {text!r})")


def env_sha(env, key):
    """The sha in env[key], exactly 40 or 64 hex chars (S-F2, R2-1, fail-closed)."""
    val = env.get(key, "")
    if not ENV_SHA_RE.fullmatch(val):
        raise GateError(f"{key} {val!r} is not exactly 40 or 64 hex characters (fail-closed)")
    return val


def is_commit(repo, ref):
    return run_git(
        repo, "rev-parse", "--verify", "--quiet", "--end-of-options", ref + "^{commit}",
    ).returncode == 0


def ensure_commit(repo, sha):
    """Fetch SHA if it is not yet a local commit; True iff it resolves."""
    if is_commit(repo, sha):
        return True
    run_git(repo, "fetch", "--no-tags", "--quiet", "--end-of-options", "origin", sha)
    return is_commit(repo, sha)


def resolve_merge_base(repo, a, b):
    """merge-base of a and b; deepen a shallow clone once. None if unresolvable."""
    proc = run_git(repo, "merge-base", "--end-of-options", a, b)
    if proc.returncode == 0:
        return proc.stdout.decode().strip()
    shallow = run_git(repo, "rev-parse", "--is-shallow-repository")
    if shallow.stdout.decode().strip() == "true":
        if run_git(repo, "fetch", "--unshallow", "--quiet").returncode != 0:
            run_git(repo, "fetch", "--deepen=2147483647", "--quiet")
        ensure_commit(repo, a)
        ensure_commit(repo, b)
        proc = run_git(repo, "merge-base", "--end-of-options", a, b)
        if proc.returncode == 0:
            return proc.stdout.decode().strip()
    return None


# ---------------------------------------------------------------------------
# Path / identifier classifiers
# ---------------------------------------------------------------------------


def is_watched_path(path):
    """True iff `path` is on the section 7 federation-wire surface."""
    return (
        path == "src/federation"
        or path.startswith("src/federation/")
        or path == "src/handlers/federation_receive.rs"
        or path == "src/handlers/federation_signing_check.rs"
    )


def changed_paths(repo, frm, to):
    """Raw NUL-delimited changed paths. --no-renames so a move of a watched
    file cannot hide as an unwatched destination-only name; -z so a non-ASCII
    or newline-bearing name cannot be C-quoted past the path globs."""
    proc = run_git(repo, "diff", "--name-only", "-z", "--no-renames", "--end-of-options", frm, to)
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", "replace").strip()
        raise GateError(f"git diff {frm} {to} exited {proc.returncode}: {err}")
    return [p.decode("utf-8", "replace") for p in proc.stdout.split(b"\0") if p]


def extract_fed_ids(repo, tree):
    """Unique AI_MEMORY_FED_* identifiers in src/ at TREE (set of str)."""
    # -a scans every blob as text: -I would take its binary/text decision from
    # attributes (a head's .gitattributes `binary` line could hide a new id,
    # #6174). The attributes file is also neutralised and textconv is off, so
    # the match is on the raw tree-object bytes only.
    proc = run_git(
        repo, "-c", "core.attributesFile=/dev/null", "grep", "-h", "-a", "--no-textconv",
        "-E", FED_ID_PATTERN, tree, "--", "src",
    )
    if proc.returncode == 1:  # no match
        return set()
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", "replace").strip()
        raise GateError(f"git grep at {tree} exited {proc.returncode}: {err}")
    return set(FED_ID_RE.findall(proc.stdout.decode("utf-8", "replace")))


def wire_drift(repo, frm, to):
    """Section 7 surface that differs between two trees: watched paths, then
    +added / -removed AI_MEMORY_FED_* identifiers. Empty list = no drift."""
    out = [p for p in changed_paths(repo, frm, to) if is_watched_path(p)]
    from_ids = extract_fed_ids(repo, frm)
    to_ids = extract_fed_ids(repo, to)
    out.extend("+" + i for i in sorted(to_ids - from_ids))
    out.extend("-" + i for i in sorted(from_ids - to_ids))
    return out


def read_blob(repo, tree, path):
    """The bytes of the regular file PATH at TREE, or None when PATH is provably absent
    there (#6977). Fail-closed: `git ls-tree` exiting 0 with empty output is the ONLY
    proof of absence. Any git failure (unresolvable tree, missing or corrupt object,
    timeout), a non-file entry (directory, symlink, submodule) or an unreadable blob
    raises GateError, so a read error can never be mistaken for a missing file."""
    listed = run_git(repo, "ls-tree", "-z", "--full-tree", "--end-of-options", tree, path)
    if listed.returncode != 0:
        err = listed.stderr.decode("utf-8", "replace").strip()
        raise GateError(f"git ls-tree {tree} {path} exited {listed.returncode}: {err}")
    entries = [e for e in listed.stdout.split(b"\0") if e]
    if not entries:
        return None
    if len(entries) != 1:
        raise GateError(f"git ls-tree {tree} {path} listed {len(entries)} entries, expected one")
    meta, _, name = entries[0].partition(b"\t")
    fields = meta.decode("ascii", "replace").split(" ")
    if len(fields) != 3 or name.decode("utf-8", "replace") != path:
        raise GateError(f"git ls-tree {tree} {path} returned an unparseable entry")
    mode, kind, sha = fields
    if kind != "blob" or mode not in REGULAR_FILE_MODES:
        raise GateError(f"{path} at {tree} is a {kind} (mode {mode}), not a regular file")
    blob = run_git(repo, "cat-file", "blob", sha)
    if blob.returncode != 0:
        err = blob.stderr.decode("utf-8", "replace").strip()
        raise GateError(f"git cat-file blob {sha} ({path} at {tree}) exited {blob.returncode}: {err}")
    return blob.stdout


def cert_banner(repo, tree):
    """(STATUS, BINDS) of the cert doc at TREE.

    STATUS: LIVE | VOID | EXPIRED | UNPARSEABLE (doc present, no STATUS line)
    | DUPLICATE (two or more STATUS lines: a decoy above the real banner must
    not be read as the banner) | ABSENT (no doc at TREE).
    BINDS: the lowercase 40-hex bound SHA, "-" when no Binds-to line matches,
    "DUPLICATE" when two or more do.
    """
    blob = read_blob(repo, tree, CERT_DOC)
    if blob is None:
        return ("ABSENT", "-")
    lines = blob.decode("utf-8", "replace").split("\n")
    statuses = [m for m in (STATUS_LINE_RE.match(ln) for ln in lines) if m]
    binds = [m for m in (BINDS_LINE_RE.match(ln) for ln in lines) if m]
    if not statuses:
        status = "UNPARSEABLE"
    elif len(statuses) == 1:
        status = statuses[0].group(1).upper()
    else:
        status = "DUPLICATE"
    if not binds:
        bound = "-"
    elif len(binds) == 1:
        bound = binds[0].group(1).lower()
    else:
        bound = "DUPLICATE"
    return (status, bound)


def fmt_banner(banner):
    return f"{banner[0]} {banner[1]}"


# ---------------------------------------------------------------------------
# The check
# ---------------------------------------------------------------------------


def check_banner_consistency(repo, judged):
    """(C) #3556: the doc's own claim at `judged` must be true. STATUS LIVE
    bound to <sha> means no section 7 wire-surface drift between <sha> and
    `judged`. Returns (ok, lines)."""
    status, binds = cert_banner(repo, judged)
    if status == "ABSENT":
        return True, [f"{PREFIX}: banner — {CERT_DOC} absent at HEAD; no live claim to check"]
    if status == "UNPARSEABLE":
        return False, [
            f"{PREFIX}: ERROR — {CERT_DOC} at HEAD has no parseable STATUS line. "
            "Expected a line shaped like '> ## STATUS — **LIVE as of …**' "
            "(blockquote, heading level, dash style, spacing and hex case are "
            "tolerated). If this change reformatted the banner, restore that "
            "shape; if it removed the banner, the document must say LIVE, VOID "
            "or EXPIRED. Fail-closed, #3556."
        ]
    if status == "DUPLICATE":
        return False, [
            f"{PREFIX}: ERROR — {CERT_DOC} at HEAD has two or more STATUS banner "
            "lines; the gate reads exactly one and will not guess which is the "
            "banner (a decoy line above the real banner is how a stale LIVE "
            "could be read as VOID). Remove the duplicate. Fail-closed, #3556."
        ]
    if status in ("VOID", "EXPIRED"):
        return True, [
            f"{PREFIX}: banner STATUS={status} — the doc makes no live claim; "
            "nothing to hold it to"
        ]
    # LIVE
    if binds == "-":
        return False, [
            f"{PREFIX}: ERROR — {CERT_DOC} at HEAD says STATUS LIVE but has no "
            "parseable Binds-to line. Expected a line shaped like "
            "'**Binds to:** `<40-hex sha>`' (spacing, backticks and hex case are "
            "tolerated). Fail-closed, #3556."
        ]
    if binds == "DUPLICATE":
        return False, [
            f"{PREFIX}: ERROR — {CERT_DOC} at HEAD has two or more Binds-to "
            "lines; the gate reads exactly one and will not guess which SHA the "
            "LIVE claim binds to. Remove the duplicate. Fail-closed, #3556."
        ]
    if not ensure_commit(repo, binds):
        return False, [
            f"{PREFIX}: ERROR — banner is LIVE bound to {binds} but that commit "
            "is not in this repository, so the claim cannot be checked "
            "(fail-closed, #3556)"
        ]
    # Ancestry is deliberately NOT required: `git diff <binds> <judged>` is a
    # tree-to-tree comparison, so a squash-merge whose watched surface equals
    # the bound tree passes on zero drift, and a bind pointed at some
    # unrelated commit (an evasion) reds on the drift it carries.
    drift = wire_drift(repo, binds, judged)
    if not drift:
        return True, [
            f"{PREFIX}: PASS — banner LIVE bound to {binds}; federation-wire "
            "surface unchanged since the bind (#3556)"
        ]
    lines = [
        f"the enterprise-federation certification claims LIVE bound to {binds} "
        f"but {len(drift)} federation-wire change(s) landed since → the "
        "certification expired per its §7 while its banner still says LIVE → "
        f"re-issue it at HEAD or record VOID/EXPIRED in {CERT_DOC}.",
        "",
        f"Bound: {binds}  HEAD: {judged}",
        ("Federation-wire drift since the bind (paths; +added / -removed "
         "AI_MEMORY_FED_* identifiers):"),
    ]
    lines.extend("  " + d for d in drift)
    lines.append("")
    lines.append(
        f"Remedy: re-run §5.4(2)–(5) at HEAD and rebind {CERT_DOC}, or set its "
        "STATUS line to VOID/EXPIRED (#3556)."
    )
    return False, lines


def pr_base_tip(repo, base, head, tip, base_name=None):
    """Validate the pull_request merge commit and return its first parent.

    The merge commit must have exactly two parents; its second parent must be
    PR_HEAD_SHA (#6138 S-F7); its first parent must be on the live base branch
    (an ancestor of, or equal to, the live tip). The first parent need not be
    the live tip: a landing on the base after the merge ref was built does not
    change what the PR contributes, so the gate stays green and measures
    first parent..merge commit (#6138 F1; strictly tighter than the landed
    gate, no vote). Anything else is not the PR's merge result (fail-closed).
    `base_name` (origin/<GITHUB_BASE_REF>) only labels the messages.
    """
    parents = git_text(repo, "rev-list", "--parents", "-n", "1", "--end-of-options", tip).split()
    if len(parents) != 3:
        raise GateError(
            f"merge commit {tip} does not have exactly two parents "
            "(not a pull_request merge result)"
        )
    first, second = parents[1], parents[2]
    head_full = git_text(repo, "rev-parse", "--verify", "--end-of-options", f"{head}^{{commit}}")
    if first == head_full:
        raise GateError(
            f"merge commit {tip} has the PR head {head_full} as its FIRST parent "
            "(reversed parents: the base branch must be the first parent); "
            "push a new commit or sync the branch with the base so GitHub rebuilds "
            "the merge ref"
        )
    if second != head_full:
        raise GateError(
            f"merge commit {tip} second parent {second} is not PR_HEAD_SHA "
            f"{head_full} (not this PR's merge result)"
        )
    live = git_text(repo, "rev-parse", "--verify", "--end-of-options", f"{base}^{{commit}}")
    anc = run_git(repo, "merge-base", "--is-ancestor", "--end-of-options", first, live)
    if anc.returncode == 1:
        raise GateError(
            f"merge commit {tip} first parent {first} is not on the live base "
            f"{base_name or 'branch'} (tip {live}); the merge ref was not built from this base: "
            "push a new commit or sync the branch with the base so GitHub "
            "rebuilds the merge ref (a re-run reuses the same GITHUB_SHA)"
        )
    if anc.returncode != 0:
        err = anc.stderr.decode("utf-8", "replace").strip()
        raise GateError(f"git merge-base --is-ancestor exited {anc.returncode}: {err}")
    return first


def check_change(repo, base, head, tip=None, base_name=None):
    """Judge the change. Without `tip` it is merge-base(base, head)..head. With
    `tip` (the pull_request merge commit, #6137) it is tip^1..tip, tip^1 being
    verified to lie on the live base and tip^2 to be the PR head. Returns
    (ok, text)."""
    judged = tip if tip else head
    refs = [base, head] + ([tip] if tip else [])
    if not all(is_commit(repo, r) for r in refs):
        return False, f"{PREFIX}: ERROR — cannot resolve range {base}..{judged} (fail-closed)"
    if tip:
        # #6137 (conductor decision): a pull_request's change is its effect on
        # the merged result, so (A)/(B) compare the merge commit's first parent
        # (on the base branch) with the merge commit. Base-side changes since
        # the fork point were judged when they landed on the base.
        try:
            mb = pr_base_tip(repo, base, head, tip, base_name)
        except GateError as exc:
            return False, f"{PREFIX}: ERROR — {exc} (fail-closed)"
    else:
        mb = resolve_merge_base(repo, base, head)
    if mb is None:
        return False, (
            f"{PREFIX}: ERROR — no merge-base for {base}..{head} "
            "(fail-closed; shallow checkout?)"
        )
    try:
        return _judge(repo, base, head, judged, mb, tip)
    except GateError as exc:
        return False, f"{PREFIX}: ERROR — {exc} (fail-closed)"


def _judge(repo, base, head, judged, mb, tip):
    watched = []
    cert_touched = False
    for p in changed_paths(repo, mb, judged):
        if p == CERT_DOC:
            cert_touched = True
        if is_watched_path(p):
            watched.append(p)
    base_ids = extract_fed_ids(repo, mb)
    head_ids = extract_fed_ids(repo, judged)
    added = sorted(head_ids - base_ids)
    removed = sorted(base_ids - head_ids)
    id_changed = bool(added or removed)

    if not watched and not id_changed:
        ok, more = check_banner_consistency(repo, judged)
        lines = [f"{PREFIX}: PASS — federation-wire surface unchanged in {mb}..{judged}"]
        return ok, "\n".join(lines + more)

    # (B) #3556: the hatch is a REAL re-issue/voiding only if the banner
    # (STATUS line or Binds-to line) differs between merge-base and judged.
    incidental = deleted = malformed = False
    banner_mb = banner_head = ("", "")
    if cert_touched:
        banner_mb = cert_banner(repo, mb)
        banner_head = cert_banner(repo, judged)
        incidental = banner_mb == banner_head
        # #3556 ruling, fix 2: a DELETED cert doc is not a voiding record.
        deleted = banner_head == ("ABSENT", "-")
        # #3556 ruling, fix 1: a banner the gate cannot read as exactly one
        # STATUS line and at most one Binds-to line is not a re-issue.
        malformed = banner_head[0] in ("DUPLICATE", "UNPARSEABLE") or banner_head[1] == "DUPLICATE"

    if cert_touched and not incidental and not deleted and not malformed:
        ok, more = check_banner_consistency(repo, judged)
        head_line = (
            f"{PREFIX}: PASS — federation-wire surface changed AND cert doc "
            f"re-issued/voided in the same change ({mb}..{judged}; banner "
            f"{fmt_banner(banner_mb)} → {fmt_banner(banner_head)})"
        )
        return ok, "\n".join([head_line] + more)

    out = [EXPIRY_SENTENCE]
    if incidental:
        out.append(
            "The cert doc WAS edited in this change, but neither its STATUS line "
            f"nor its Binds-to line changed (banner {fmt_banner(banner_head)} at "
            "both ends) — an incidental edit is not a re-issue and not a voiding "
            "record (#3556)."
        )
    if deleted:
        out.append(
            "The cert doc is ABSENT at HEAD (deleted in this change) while the "
            "federation-wire surface changed — deleting the certification is not "
            "a voiding record; record VOID/EXPIRED in the document instead (#3556)."
        )
    if malformed:
        out.append(
            "The cert doc at HEAD does not carry exactly one STATUS banner line "
            f"and at most one Binds-to line (parsed: {fmt_banner(banner_head)}) — "
            "the gate reads one banner and will not guess; a duplicated or "
            "unparseable banner is not a re-issue and not a voiding record (#3556)."
        )
    out.append("")
    if tip:
        out.append(
            f"Range: {mb}..{judged}  (first parent to the pull_request merge commit; "
            "judged at the pull_request merge commit)"
        )
    else:
        out.append(f"Range: {mb}..{judged}  (merge-base of {base} and {head})")
    if watched:
        out.append("Watched federation-wire paths touched:")
        out.extend("  " + w for w in watched)
    if id_changed:
        out.append("AI_MEMORY_FED_* identifiers added/removed/renamed in src/:")
        out.extend("  + " + a for a in added)
        out.extend("  - " + r for r in removed)
    out.append("")
    out.append(
        f"Remedy: modify {CERT_DOC} in this same change (re-issue against the "
        "new SHA, or record the voiding)."
    )
    return False, "\n".join(out)


# ---------------------------------------------------------------------------
# Range resolution
# ---------------------------------------------------------------------------


class Skip(Exception):
    """N/A: no range to check (not a failure)."""


def _need(env, key, why):
    val = env.get(key, "")
    if not val:
        raise GateError(f"{key} is unset on {why} (fail-closed)")
    return val


def resolve_live_base(repo, base_ref):
    """Sha of the LIVE base ref origin/<base_ref>, fetched explicitly if absent."""
    if base_ref.startswith("-") or ".." in base_ref or any(c.isspace() for c in base_ref):
        raise GateError(f"GITHUB_BASE_REF {base_ref!r} is not a plain branch name (fail-closed)")
    tracking = f"refs/remotes/origin/{base_ref}"
    if not is_commit(repo, tracking):
        run_git(
            repo, "fetch", "--no-tags", "--quiet", "--end-of-options", "origin",
            f"+refs/heads/{base_ref}:{tracking}",
        )
    if not is_commit(repo, tracking):
        raise GateError(
            f"cannot resolve the live base ref origin/{base_ref} (fetch failed; fail-closed)"
        )
    return git_text(repo, "rev-parse", "--verify", "--end-of-options", tracking + "^{commit}")


def resolve_range(repo, env):
    """(base, head, tip) for the change under test. tip is the commit that
    (B)/(C) are judged at (None = judge at head). Raises Skip / GateError."""
    event = env.get("GITHUB_EVENT_NAME", "")
    # #5970 (precedent: PR #5871 head 3be284991): inside GitHub Actions the
    # event payload names the range, so a CERT_EXPIRY_BASE / CERT_EXPIRY_HEAD
    # override is refused (even an empty one); outside CI it is honoured.
    in_ci = "GITHUB_ACTIONS" in env
    if in_ci:
        refused = [k for k in ("CERT_EXPIRY_BASE", "CERT_EXPIRY_HEAD") if k in env]
        if refused:
            raise GateError(
                f"refused (#5970, fail-closed): {', '.join(refused)} set in the gate's "
                "environment under GitHub Actions; the range comes only from the "
                "event payload"
            )
    if env.get("CERT_EXPIRY_BASE"):
        return env["CERT_EXPIRY_BASE"], env.get("CERT_EXPIRY_HEAD") or "HEAD", None

    if event == "pull_request":
        # #6137: judge the merge commit the job checked out, against the LIVE
        # base ref, not the (possibly stale) payload PR_BASE_SHA.
        _need(env, "PR_HEAD_SHA", "a pull_request event")
        head = env_sha(env, "PR_HEAD_SHA")
        base_ref = _need(env, "GITHUB_BASE_REF", "a pull_request event")
        tip = env_sha(env, "GITHUB_SHA") if env.get("GITHUB_SHA") else "HEAD"
        stale = env_sha(env, "PR_BASE_SHA") if env.get("PR_BASE_SHA") else ""
        base = resolve_live_base(repo, base_ref)
        if not is_commit(repo, head):
            ensure_commit(repo, head)
        if not is_commit(repo, head):
            raise GateError(f"PR_HEAD_SHA {head} does not resolve to a commit (fail-closed)")
        if not is_commit(repo, tip):
            raise GateError(f"merge commit {tip} does not resolve to a commit (fail-closed)")
        # The merge commit's parent structure (two parents, second parent ==
        # PR_HEAD_SHA, first parent on the live base) is verified in pr_base_tip.
        if stale and stale != base:
            print(
                f"{PREFIX}: note — payload PR_BASE_SHA {stale} differs from the live "
                f"base origin/{base_ref} {base}; using the live base (#6137)",
                file=sys.stderr,
            )
        return base, head, tip

    if event == "push":
        before = env.get("GITHUB_EVENT_BEFORE", "")
        if not before or ZERO_SHA_RE.match(before):
            raise Skip("push has no previous tip (new branch / first push); skip")
        before = env_sha(env, "GITHUB_EVENT_BEFORE")
        after = env_sha(env, "GITHUB_SHA") if env.get("GITHUB_SHA") else "HEAD"
        return before, after, None
    if event == "workflow_dispatch":
        raise Skip(
            "workflow_dispatch has no PR/push range (outside CI, CERT_EXPIRY_BASE/HEAD "
            "check a range by hand; they are refused under GitHub Actions); skip"
        )
    if event == "":
        if in_ci:
            raise GateError(
                "GITHUB_EVENT_NAME is empty in a CI run; the event payload is the "
                "only range source under GitHub Actions (fail-closed)"
            )
        # Local convenience: standard PR-shaped range vs the tracking branch or
        # origin/release/v1.0.0. Never invent a range against the pinned SHA.
        for ref in ("@{upstream}", "origin/release/v1.0.0"):
            if is_commit(repo, ref):
                return git_text(repo, "rev-parse", "--verify", "--end-of-options", ref), "HEAD", None
        raise Skip(
            "no CERT_EXPIRY_BASE, no @{upstream}, no origin/release/v1.0.0; skip"
        )
    raise Skip(f"event '{event}' has no PR/push range; skip")


def run_gate(repo, env):
    """Returns (rc, stdout_text, stderr_text)."""
    try:
        require_git_version(repo)
        base, head, tip = resolve_range(repo, env)
    except Skip as skip:
        return 0, "", f"{PREFIX}: N/A — {skip}"
    except GateError as exc:
        return 1, "", f"{PREFIX}: ERROR — {exc}"
    base_name = f"origin/{env['GITHUB_BASE_REF']}" if tip is not None else None
    ok, text = check_change(repo, base, head, tip, base_name)
    return (0, text, "") if ok else (1, "", text)


def platform_path_max():
    """The platform's PATH_MAX: 1024 on macOS and the BSDs, 4096 elsewhere (R5-F1)."""
    bsd = ("darwin", "freebsd", "openbsd", "netbsd")
    return 1024 if sys.platform.startswith(bsd) else 4096


def path_max(path):
    """The PATH_MAX of the filesystem holding path (Linux 4096, macOS 1024),
    falling back to the platform's value when os.pathconf cannot say (#6145 R4-F1,
    R5-F1), so the fallback never exceeds the real limit."""
    try:
        limit = os.pathconf(str(path), "PC_PATH_MAX")
    except (OSError, ValueError, AttributeError):
        return platform_path_max()
    return limit if isinstance(limit, int) and limit > 0 else platform_path_max()


@contextlib.contextmanager
def directory_descriptor(path, parent=None):
    """Own one directory descriptor and release it even when traversal fails."""
    descriptor = os.open(path, os.O_RDONLY, dir_fd=parent)
    try:
        yield descriptor
    finally:
        os.close(descriptor)


def deep_scratch(tmp, target_len):
    """Build an exact-length path with a lexical owner for every descriptor."""
    base = Path(tempfile.mkdtemp(prefix="gitshim-deep.", dir=str(tmp)))

    def descend(cur, cur_len, component, parent=None):
        """Unwind every directory owner even if an inner traversal or close fails."""
        with directory_descriptor(component, parent) as descriptor:
            if cur_len == target_len:
                return cur
            if cur_len > target_len:
                raise OSError(errno.ENAMETOOLONG,
                              f"the scratch base is {cur_len} bytes, over the {target_len}-byte target")
            room = target_len - cur_len
            step = min(200, room - 1)
            if room - step - 1 == 1:
                step -= 1  # a final component needs 2 bytes ('/' + 1 char)
            if step < 1:
                raise OSError(errno.ENAMETOOLONG,
                              f"cannot land on exactly {target_len} bytes from {cur_len}")
            name = "d" * step
            os.mkdir(name, dir_fd=descriptor)
            return descend(cur / name, cur_len + 1 + step, name, descriptor)

    try:
        return base, descend(base, len(os.fsencode(str(base))), str(base))
    except BaseException:
        shutil.rmtree(base, ignore_errors=True)
        raise


# ---------------------------------------------------------------------------
# Self-test: a thin runner over the external corpus (#6357, #6445)
# ---------------------------------------------------------------------------

CORPUS_HARNESS = Path("scripts") / "ci" / "tests" / "test_check_cert_expiry_corpus.py"
CORPUS_TIMEOUT_S = 1800
SELF_TEST_FAIL_RC = 2
CORPUS_FAIL_PREFIX = "CORPUS-FAIL "
CORPUS_SUMMARY_PREFIX = "CORPUS-SUMMARY "
MAX_FAILURES_SHOWN = 20
SELF_TEST_OK = "check-cert-expiry self-test OK: {summary}; corpus {harness}"


def self_test():
    """Run the external corpus (scripts/ci/tests/test_check_cert_expiry_corpus.py)
    in a child interpreter, one scratch repository per case, and report each failing
    case by name. rc 0 when every case holds, 2 otherwise. The child's traceback is
    never relayed: a crashing case is a named failure and the rest still run."""
    harness = Path(__file__).resolve().parent.parent / CORPUS_HARNESS
    if not harness.is_file():
        print(f"check-cert-expiry self-test FAILED (corpus missing: {CORPUS_HARNESS})",
              file=sys.stderr)
        return SELF_TEST_FAIL_RC
    try:
        proc = subprocess.run(
            [sys.executable, "-I", str(harness), "--machine"],
            capture_output=True, timeout=CORPUS_TIMEOUT_S, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(f"check-cert-expiry self-test FAILED (corpus could not run: {exc})",
              file=sys.stderr)
        return SELF_TEST_FAIL_RC
    lines = proc.stdout.decode("utf-8", "replace").splitlines()
    failed = [ln[len(CORPUS_FAIL_PREFIX):] for ln in lines if ln.startswith(CORPUS_FAIL_PREFIX)]
    summary = [ln[len(CORPUS_SUMMARY_PREFIX):] for ln in lines
               if ln.startswith(CORPUS_SUMMARY_PREFIX)]
    if failed or proc.returncode != 0 or not summary:
        for entry in failed[:MAX_FAILURES_SHOWN]:
            print(f"self-test FAILED ({entry})", file=sys.stderr)
        if len(failed) > MAX_FAILURES_SHOWN:
            print(f"self-test FAILED (+{len(failed) - MAX_FAILURES_SHOWN} more cases)",
                  file=sys.stderr)
        if not failed:
            print(f"self-test FAILED (corpus exited {proc.returncode} without a summary)",
                  file=sys.stderr)
        print("check-cert-expiry self-test: FAIL", file=sys.stderr)
        return SELF_TEST_FAIL_RC
    print(SELF_TEST_OK.format(summary=summary[-1], harness=CORPUS_HARNESS))
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Enterprise-federation certification section 7 expiry gate.")
    parser.add_argument("--self-test", action="store_true",
                        help="run the external corpus (one scratch repository per case)")
    args = parser.parse_args(argv)
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            # StringIO and closed streams cannot reconfigure; keep their existing encoding.
            continue
    if args.self_test:
        return self_test()
    rc, out, err = run_gate(REPO_ROOT, dict(os.environ))
    if out:
        print(out)
    if err:
        print(err, file=sys.stderr)
    return rc


if __name__ == "__main__":
    sys.exit(main())
