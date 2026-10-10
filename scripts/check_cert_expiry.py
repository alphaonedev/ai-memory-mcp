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
    in src/  (names new to the judged commit, and names gone from it or
    that lost an occurrence line, keyed on (identifier, trimmed line text), at
    merge-base vs the judged commit)

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

WHAT THIS DOES NOT CLAIM. The identifier check compares, per identifier, the
trimmed text of every line under src/ that names it (#6427). So a value edited
on the line that carries an AI_MEMORY_FED_* identifier, a rewrap of that line,
a trailing comment on it, or a block comment opened and closed ON it is drift
and RED unless the old line text still occurs elsewhere under src/; a value
that sits on a different line from the name is not seen. The base's
identifier-bearing line texts are compared as a multiset over all of src/,
without the path: a change that keeps every one of them, as often as before,
somewhere under src/ (in any file, in a comment, in a string, or in code that
is compiled out) is not seen, and the (value-copy-bound) cell pins that (a
value edited with the old line kept in a block comment is GREEN, #6652).
LEXICAL BOUND: the check is a text scan, so a change that leaves every
identifier-bearing line byte-identical is not seen. Measured examples, each
GREEN: a multi-line comment opened and closed on the neighbouring lines, an
attribute that compiles the definition out added on the line above, a raw-string
wrap, and a move of the line into a file that is not compiled (tracked in
#6560). A block comment AROUND a definition is therefore caught only in the
same-line form. This gate does not re-run 5.4(2)-(5); it only forces the
cert-doc to be touched so a human/re-issue cannot be skipped.

Usage:
  scripts/check_cert_expiry.py              # against the resolved range
  scripts/check_cert_expiry.py --self-test  # plant-a-violation in a scratch
                                            # repository (never a real branch)

Exit codes: 0 clean / N/A-skip, 1 violation, 2 usage / self-test failure.
"""

import argparse
import collections
import contextlib
import io
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import unittest.mock
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

CERT_DOC = "docs/compliance/ENTERPRISE-FEDERATION-CERTIFICATION.md"
FED_ID_PATTERN = "AI_MEMORY_FED_[A-Z0-9_]+"
# Left word boundary (#6427): a longer token that merely ends in an identifier
# (NOTAI_MEMORY_FED_X) is not a mention of it. git grep still selects lines with
# the unanchored FED_ID_PATTERN; the match itself is taken here.
FED_ID_RE = re.compile(r"(?<![A-Za-z0-9_])" + FED_ID_PATTERN)
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


def extract_fed_id_counts(repo, tree):
    """Occurrences of each AI_MEMORY_FED_* identifier in src/ at TREE
    (Counter: (identifier, trimmed line text) -> number of occurrences).

    -a, never -I (#6174): for a tree argument git takes binary-ness from the
    WORKING-TREE attributes, which on pull_request belong to the change under
    test, so -I let that change hide src/ from the scan. Reading binaries adds
    their matches to BOTH trees' counts; it does not by itself widen or narrow
    the drift. Occurrences, not just names (#6370): a name that merely survives
    in a comment elsewhere must not hide the removal of its definition. Keyed on
    the trimmed line as well as the name (#6427): a single global count per name
    could be offset by a mention added anywhere else, so a line that carried a
    name and is gone from the head is a loss whatever else mentions the name.
    Lines are compared without their path, so moving a line between files and
    re-indenting it is not drift."""
    proc = run_git(repo, "grep", "-h", "-a", "-E", FED_ID_PATTERN, tree, "--", "src")
    if proc.returncode == 1:  # no match
        return collections.Counter()
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", "replace").strip()
        raise GateError(f"git grep at {tree} exited {proc.returncode}: {err}")
    counts = collections.Counter()
    for line in proc.stdout.decode("utf-8", "replace").split("\n"):
        text = line.strip()
        for name in FED_ID_RE.findall(text):
            counts[(name, text)] += 1
    return counts


def fed_id_delta(base_counts, head_counts):
    """(added, removed) identifier drift between two keyed occurrence Counters.

    added: names new to the head. removed: names gone from the head, and names
    that lost an occurrence line: some (name, trimmed line) pair has fewer
    matches at the head than at the base (the definition may have been removed,
    replaced by a comment or wrapped in one while a mention elsewhere still
    names it, #6370, #6427). Such a name carries the count change. An extra
    mention of an existing name, or a line moved between files, is not drift."""
    base_names = collections.Counter()
    head_names = collections.Counter()
    for (name, _), n in base_counts.items():
        base_names[name] += n
    for (name, _), n in head_counts.items():
        head_names[name] += n
    added = sorted(set(head_names) - set(base_names))
    lost = collections.Counter()
    for (name, text), before in base_counts.items():
        if head_counts.get((name, text), 0) < before:
            lost[name] += before - head_counts.get((name, text), 0)
    removed = []
    for name in sorted(base_names):
        before, after = base_names[name], head_names.get(name, 0)
        if after == 0:
            removed.append(name)
        elif lost[name]:
            if after < before:
                removed.append(f"{name} (occurrences in src/ fell {before} -> {after})")
            else:
                removed.append(f"{name} ({lost[name]} occurrence(s) on lines that changed or no "
                               f"longer exist in src/; the total did not fall: {before} -> {after})")
    return added, removed


def wire_drift(repo, frm, to):
    """Section 7 surface that differs between two trees: watched paths, then
    +added / -removed AI_MEMORY_FED_* identifiers. Empty list = no drift."""
    out = [p for p in changed_paths(repo, frm, to) if is_watched_path(p)]
    added, removed = fed_id_delta(extract_fed_id_counts(repo, frm),
                                  extract_fed_id_counts(repo, to))
    out.extend("+" + i for i in added)
    out.extend("-" + i for i in removed)
    return out


def cert_banner(repo, tree):
    """(STATUS, BINDS) of the cert doc at TREE.

    STATUS: LIVE | VOID | EXPIRED | UNPARSEABLE (doc present, no STATUS line)
    | DUPLICATE (two or more STATUS lines: a decoy above the real banner must
    not be read as the banner) | ABSENT (no doc at TREE).
    BINDS: the lowercase 40-hex bound SHA, "-" when no Binds-to line matches,
    "DUPLICATE" when two or more do.
    """
    proc = run_git(repo, "show", "--end-of-options", f"{tree}:{CERT_DOC}")
    if proc.returncode != 0:
        return ("ABSENT", "-")
    lines = proc.stdout.decode("utf-8", "replace").split("\n")
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
        "Federation-wire drift since the bind (paths; +added / -removed "
        "AI_MEMORY_FED_* identifiers):",
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
    added, removed = fed_id_delta(extract_fed_id_counts(repo, mb),
                                  extract_fed_id_counts(repo, judged))
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


# ---------------------------------------------------------------------------
# Plant-a-violation self-test (scratch repository; never a real branch)
# ---------------------------------------------------------------------------


class Fixture:
    """A throwaway repository the self-test plants violations in."""

    def __init__(self, repo):
        self.repo = repo

    def g(self, *args):
        proc = run_git(self.repo, *args)
        if proc.returncode != 0:
            err = proc.stderr.decode("utf-8", "replace").strip()
            raise GateError(f"fixture git {args} failed: {err}")
        return proc.stdout.decode("utf-8", "replace").strip()

    def write(self, rel, text, append=False):
        path = self.repo / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a" if append else "w", encoding="utf-8") as fh:
            fh.write(text)

    def commit(self, paths, msg):
        self.g("add", "--", *paths)
        self.g("commit", "-q", "-m", msg)
        return self.g("rev-parse", "HEAD")

    def reset(self, sha):
        self.g("reset", "-q", "--hard", sha)

    def banner(self, status, binds, extra=""):
        """The cert doc in its real shape (the gate READS the banner)."""
        self.write(
            CERT_DOC,
            "# Enterprise federation certification (fixture)\n\n"
            f"**Binds to:** `{binds}` (fixture bind)\n\n"
            f"> ## STATUS — **{status} as of 2026-01-01** (fixture)\n\n"
            f"Body prose.\n{extra}",
        )

    def prepend(self, rel, line):
        path = self.repo / rel
        path.write_text(line + "\n" + path.read_text(encoding="utf-8"), encoding="utf-8")

    def merge(self, other, msg):
        self.g("merge", "-q", "--no-ff", "-m", msg, other)
        return self.g("rev-parse", "HEAD")


class SelfTest:
    def __init__(self):
        self.failed = False

    def fail(self, msg, out=None):
        print(f"self-test FAILED {msg}", file=sys.stderr)
        if out:
            print(out, file=sys.stderr)
        self.failed = True

    def expect_red(self, label, desc, repo, base, head, needles, tip=None):
        ok, out = check_change(repo, base, head, tip)
        if ok:
            self.fail(f"({label}): {desc} was NOT rejected", out)
            return out
        for needle, why in needles:
            if needle not in out:
                self.fail(f"({label}): rejection {why}:", out)
        return out

    def expect_green(self, label, desc, repo, base, head, needles=(), tip=None):
        ok, out = check_change(repo, base, head, tip)
        if not ok:
            self.fail(f"({label}): {desc} was REJECTED:", out)
            return out
        for needle, why in needles:
            if needle not in out:
                self.fail(f"({label}): pass output {why}:", out)
        return out


    def gate(self, label, why, repo, env, needle=None):
        """Run the whole gate. needle None: it must pass. Else it must fail
        closed (rc 1) AND say `needle` (a fail-closed for the wrong reason, or
        a wrong remedy, is a defect too)."""
        rc, out, err = run_gate(repo, env)
        text = out + err
        if needle is None:
            if rc != 0:
                self.fail(f"({label}): {why} was REJECTED:", text)
        elif rc == 0:
            self.fail(f"({label}): {why} did not fail closed", text)
        elif needle not in text:
            self.fail(f"({label}): {why} failed for the wrong reason (wanted {needle!r}):", text)
        return text


class FailureRecorder:
    """Stand-in for SelfTest that records failures instead of printing them,
    so a cell can assert that a helper reports exactly one named failure
    without polluting the real self-test output (#6380)."""

    def __init__(self):
        self.messages = []

    def fail(self, msg, out=None):
        self.messages.append(msg)


GIT_SHIM = """#!{python}
import os, sys
real, argv = {real!r}, sys.argv[1:]
if {probe!r} in argv:
    print({marker!r})
    sys.exit(0)
if "--version" in argv and {version!r}:
    print({version!r})
    sys.exit(0)
if {fail!r} and {fail!r} in argv:
    sys.stderr.write("fatal: shim refuses " + {fail!r} + chr(10))
    sys.exit(128)
os.execv(real, [real] + argv)
"""


GIT_SHIM_PROBE_ARG = "--gitshim-probe"


GIT_SHIM_PROBE_TIMEOUT = 60


def _require_shim_reachable(path, marker, timeout=GIT_SHIM_PROBE_TIMEOUT):
    """Positive probe (#6379): `git` looked up on `path` must be the shim, which
    answers GIT_SHIM_PROBE_ARG with this run's `marker` (a per-run random nonce,
    #6567/#6562) and nothing else. The answer is compared exactly (`marker` plus
    one newline) on stdout only, byte for byte, so a decoy git that echoes a
    constant, pads or affixes the marker (a CR before the newline included),
    changes its case, or writes it to stderr is refused (#6651). Any cause that makes
    the shim unreachable (not executable, an exec-refusing mount, a split PATH
    entry) lets lookup fall through to the real git; refuse by name so the cells
    never blame the gate for it. Output is decoded with errors="replace" so a
    git that writes non-UTF-8 bytes is a named refusal, never a crash (#6428)."""
    try:
        proc = subprocess.run(["git", GIT_SHIM_PROBE_ARG], capture_output=True,
                              env=dict(os.environ, PATH=path), timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise GateError(f"the git shim is not the git on PATH (probe failed: {exc})") from exc
    answer = proc.stdout.decode("utf-8", errors="replace")
    if proc.returncode != 0 or answer != marker + "\n":
        raise GateError("the git shim is not the git on PATH (the probe "
                        f"{GIT_SHIM_PROBE_ARG!r} did not reach the shim; check that the "
                        "scratch directory allows executing files)")


def run_gate_shimmed(tmp, repo, env, version="", fail=""):
    """run_gate with a PATH shim `git` that reports `version` for --version
    and exits 128 on any call whose argv contains `fail`, and otherwise
    delegates to the real git (R2-F2: pins the guarded branches). One
    try/finally owns the shim directory from creation, so any exception
    removes it, not only GateError (#6428)."""
    real = shutil.which("git")
    if real is None:
        raise GateError("git is not on PATH")
    shim_dir = Path(tempfile.mkdtemp(prefix="gitshim.", dir=str(tmp)))
    marker = secrets.token_hex(16)
    saved = os.environ.get("PATH")
    try:
        if os.pathsep in str(shim_dir):
            # #6178: the PATH entry would be split and the real git would run.
            raise GateError(f"the scratch path {str(shim_dir)!r} contains the PATH separator "
                            f"{os.pathsep!r}; the git shim would be unreachable (run the "
                            f"self-test from a checkout whose path has no {os.pathsep!r})")
        shim = shim_dir / "git"
        shim.write_text(GIT_SHIM.format(python=sys.executable, real=real, version=version,
                                        fail=fail, probe=GIT_SHIM_PROBE_ARG,
                                        marker=marker), encoding="utf-8")
        shim.chmod(0o755)
        shim_path = f"{shim_dir}{os.pathsep}{saved or ''}"
        _require_shim_reachable(shim_path, marker)
        os.environ["PATH"] = shim_path
        return run_gate(repo, dict(env, PATH=os.environ["PATH"]))
    finally:
        if saved is None:
            os.environ.pop("PATH", None)
        else:
            os.environ["PATH"] = saved
        shutil.rmtree(shim_dir, ignore_errors=True)


def shimmed_cell(t, label, tmp, repo, env, **kw):
    """run_gate_shimmed for a self-test cell; a shim that cannot be installed
    is a named self-test failure recorded on `t` and returns None, never a
    verdict on the gate (#6178, #6380)."""
    try:
        return run_gate_shimmed(tmp, repo, env, **kw)
    except GateError as exc:
        t.fail(f"({label}): the git shim could not be installed: {exc}")
        return None


def _shim_nonce_freshness(t, tmp, repo, env):
    """(shim-probe-exact, #6567): two shimmed runs must hand the probe two
    distinct 32-hex-digit markers (a module constant would repeat). Each run
    goes through shimmed_cell, so a shim that cannot be reached is a named
    (shim-probe-exact) failure on `t`, never an escaped exception (#6650)."""
    seen_markers = []
    real_probe = _require_shim_reachable

    def spy_probe(path, marker, timeout=GIT_SHIM_PROBE_TIMEOUT):
        seen_markers.append(marker)
        return real_probe(path, marker, timeout)

    with unittest.mock.patch.object(sys.modules[__name__], "_require_shim_reachable",
                                    side_effect=spy_probe):
        for _ in range(2):
            shimmed_cell(t, "shim-probe-exact", tmp, repo, env, version="git version 2.29.9")
    if (len(seen_markers) != 2 or seen_markers[0] == seen_markers[1]
            or not all(re.fullmatch("[0-9a-f]{32}", m) for m in seen_markers)):
        t.fail(f"(shim-probe-exact): the probe marker is not a fresh 32-hex nonce per "
               f"run: {seen_markers!r}")


def _gate_env(**kw):
    return {k: v for k, v in kw.items() if v is not None}


def self_test():
    try:
        require_git_version(REPO_ROOT)
    except GateError as exc:
        print(f"{PREFIX}: ERROR — {exc}", file=sys.stderr)
        return 2
    scratch_root = REPO_ROOT / ".local-runs"
    scratch_root.mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile.mkdtemp(prefix="cert-expiry-selftest.", dir=str(scratch_root)))
    try:
        return _self_test(tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _self_test(tmp):  # noqa: C901 - one linear plant-a-violation corpus
    repo = tmp / "repo"
    repo.mkdir()
    t = SelfTest()
    fx = Fixture(repo)
    fx.g("init", "-q", "-b", "main")
    fx.g("config", "user.name", "Cert Expiry Selftest")
    fx.g("config", "user.email", "selftest@invalid.example")
    fx.g("config", "commit.gpgsign", "false")

    fx.write("src/federation/mod.rs", "fn federation_mod() {}\n")
    fx.write("src/handlers/federation_receive.rs", "fn receive() {}\n")
    fx.write("src/handlers/federation_signing_check.rs", "fn signing_check() {}\n")
    fx.write("src/config.rs", 'pub const X: &str = "AI_MEMORY_FED_REQUIRE_SIG";\n')
    fx.write("src/unrelated.rs", "fn other() {}\n")
    genesis = fx.commit(["src"], "genesis")

    # The base fixture is LIVE and bound to the genesis tree, so a range from
    # base carries no wire drift since the bind ((C) is true).
    fx.banner("LIVE", genesis)
    base = fx.commit([CERT_DOC], "base: certification LIVE bound to genesis")

    sentence = "federation-wire surface changed → the enterprise-federation certification expires per its §7"
    mod_rs = "src/federation/mod.rs"

    # (a) RED - watched federation path, no cert-doc touch.
    fx.write(mod_rs, "// mutate\n", append=True)
    viol = fx.commit([mod_rs], "violate: touch src/federation without cert doc")
    t.expect_red("a", "watched-path violation", repo, base, viol, [
        (sentence, "did not carry the required §7 expiry sentence"),
        (mod_rs, "did not name the watched path"),
    ])

    # (b) GREEN - same violation PLUS a REAL re-issue: the doc rebinds to the
    #     wire-change commit.
    fx.banner("LIVE", viol)
    satisfied = fx.commit([CERT_DOC], "satisfy: re-issue cert doc alongside wire change")
    t.expect_green("b", "cert-doc-touching variant", repo, base, satisfied, [
        ("cert doc re-issued/voided", "did not name the cert-doc satisfy path"),
    ])
    fx.reset(base)

    # (c) RED - AI_MEMORY_FED_* identifier added in src/ OUTSIDE the path watches.
    fx.write("src/config.rs", 'pub const X: &str = "AI_MEMORY_FED_REQUIRE_SIG";\n'
             'pub const Y: &str = "AI_MEMORY_FED_NEW_KNOB";\n')
    id_sha = fx.commit(["src/config.rs"], "violate: add AI_MEMORY_FED_* identifier")
    t.expect_red("c", "identifier-add violation", repo, base, id_sha, [
        ("AI_MEMORY_FED_NEW_KNOB", "did not name the added identifier"),
        (sentence, "did not carry the required §7 expiry sentence"),
    ])

    # (d) GREEN - identifier add + a real re-issue (rebind to the add).
    fx.banner("LIVE", id_sha)
    id_ok = fx.commit([CERT_DOC], "satisfy: re-issue cert doc alongside identifier add")
    t.expect_green("d", "identifier-add + cert-doc variant", repo, base, id_ok)
    fx.reset(base)

    # (e) GREEN - unrelated src/ edit.
    fx.write("src/unrelated.rs", "// unrelated\n", append=True)
    clean = fx.commit(["src/unrelated.rs"], "clean: unrelated src edit")
    t.expect_green("e", "unrelated src edit", repo, base, clean, [
        ("federation-wire surface unchanged", "did not say the surface was unchanged"),
    ])
    fx.reset(base)

    # (f) GREEN - cert-doc-only change.
    fx.write(CERT_DOC, "// docs only\n", append=True)
    docs = fx.commit([CERT_DOC], "clean: cert-doc only")
    t.expect_green("f", "cert-doc-only change", repo, base, docs)
    fx.reset(base)

    # (g) RED - federation_receive.rs.
    fx.write("src/handlers/federation_receive.rs", "// mutate receive\n", append=True)
    recv = fx.commit(["src/handlers/federation_receive.rs"], "violate: touch federation_receive.rs")
    t.expect_red("g", "federation_receive.rs violation", repo, base, recv, [
        ("src/handlers/federation_receive.rs", "did not name federation_receive.rs"),
    ])
    fx.reset(base)

    # (h) RED - federation_signing_check.rs.
    fx.write("src/handlers/federation_signing_check.rs", "// mutate signing\n", append=True)
    sign = fx.commit(["src/handlers/federation_signing_check.rs"],
                     "violate: touch federation_signing_check.rs")
    t.expect_red("h", "federation_signing_check.rs violation", repo, base, sign, [
        ("src/handlers/federation_signing_check.rs", "did not name federation_signing_check.rs"),
    ])
    fx.reset(base)

    # (h2) RED - nested path under src/federation/** (a non-recursive glob would
    #      let src/federation/identity/*.rs through).
    fx.write("src/federation/identity/mod.rs", "fn identity() {}\n")
    nested = fx.commit(["src/federation/identity/mod.rs"],
                       "violate: touch nested src/federation/identity")
    t.expect_red("h2", "nested src/federation/identity/mod.rs", repo, base, nested, [
        ("src/federation/identity/mod.rs", "did not name the nested watched path"),
    ])
    fx.reset(base)

    # (i) RED - rename of a watched file (D of the old path must still trip).
    (repo / "src/elsewhere").mkdir(parents=True, exist_ok=True)
    fx.g("mv", mod_rs, "src/elsewhere/mod.rs")
    fx.g("commit", "-q", "-m", "violate: rename watched federation file away")
    rename = fx.g("rev-parse", "HEAD")
    t.expect_red("i", "watched-file rename", repo, base, rename, [
        (mod_rs, "rename rejection did not name the old watched path"),
    ])
    fx.reset(base)

    # (j) RED - identifier RENAME (remove one, add another).
    fx.write("src/config.rs", 'pub const X: &str = "AI_MEMORY_FED_REQUIRE_SIGNATURE";\n')
    idren = fx.commit(["src/config.rs"], "violate: rename AI_MEMORY_FED_* identifier")
    t.expect_red("j", "identifier-rename", repo, base, idren, [
        ("AI_MEMORY_FED_REQUIRE_SIGNATURE", "did not name the added identifier"),
        ("AI_MEMORY_FED_REQUIRE_SIG", "did not name the removed identifier"),
    ])
    fx.reset(base)

    # (p) RED - non-ASCII path under a watched dir. core.quotePath would
    #     C-quote it and the path match would MISS; the gate reads raw -z paths.
    fx.write("src/federation/naïve_wire.rs", "fn wire() {}\n")
    quoted = fx.commit(["src/federation/naïve_wire.rs"], "violate: non-ASCII watched path")
    t.expect_red("p", "non-ASCII watched path (core.quotePath bypass)", repo, base, quoted, [
        ("src/federation/naïve_wire.rs", "did not name the raw (unquoted) non-ASCII path"),
    ])

    # ---- #3556 predicates (B) and (C) ----------------------------------

    # (q) RED - wire change + an INCIDENTAL cert-doc edit (banner untouched).
    fx.write(mod_rs, "// mutate\n", append=True)
    fx.banner("LIVE", genesis, "An incidental prose edit.\n")
    incidental = fx.commit([mod_rs, CERT_DOC], "violate: wire change + incidental doc edit")
    t.expect_red("q", "wire change + incidental cert-doc edit (#3556 hole open)", repo, base,
                 incidental, [
        ("an incidental edit is not a re-issue and not a voiding record",
         "did not name the incidental edit"),
        (sentence, "did not carry the required §7 expiry sentence"),
    ])
    fx.reset(base)

    # (r) GREEN - wire change + the STATUS line flipped to VOID.
    fx.write(mod_rs, "// mutate\n", append=True)
    fx.banner("VOID", genesis)
    void = fx.commit([mod_rs, CERT_DOC], "satisfy: wire change + VOID record")
    t.expect_green("r", "wire change + VOID record", repo, base, void, [
        ("banner STATUS=VOID", "did not report the VOID banner"),
    ])

    # (t) GREEN - an unrelated change ON TOP of the VOID record.
    fx.write("src/unrelated.rs", "// unrelated\n", append=True)
    over_void = fx.commit(["src/unrelated.rs"], "clean: unrelated edit over a VOID record")
    t.expect_green("t", "unrelated change over a VOID banner", repo, void, over_void)
    fx.reset(base)

    # (s) RED - LIVE banner + wire drift since the bind, on a range that touches
    #     NOTHING watched.
    fx.write(mod_rs, "// mutate\n", append=True)
    drifted = fx.commit([mod_rs], "earlier: wire change with no re-issue")
    fx.write("src/unrelated.rs", "// unrelated\n", append=True)
    stale_live = fx.commit(["src/unrelated.rs"], "later: unrelated edit over a stale LIVE banner")
    t.expect_red("s", "LIVE banner over wire drift (#3556 hole open)", repo, drifted, stale_live, [
        (f"claims LIVE bound to {genesis} but 1 federation-wire change(s) landed since",
         "did not name the bound SHA and the drift count"),
        ("while its banner still says LIVE", "did not carry the banner-vs-drift sentence"),
        (mod_rs, "did not list the drifted path"),
    ])

    # (u) GREEN - the same stale state HEALED by a STATUS flip to EXPIRED.
    fx.banner("EXPIRED", genesis)
    healed = fx.commit([CERT_DOC], "heal: record EXPIRED")
    t.expect_green("u", "recording EXPIRED over the stale LIVE banner", repo, stale_live, healed)
    fx.reset(base)

    # (v1) GREEN - LIVE bound to a non-ancestor whose watched tree equals HEAD's
    #      (squash-merge shape): drift is a tree comparison.
    fx.g("checkout", "-q", "-b", "side", genesis)
    fx.write("src/unrelated.rs", "// side\n", append=True)
    side = fx.commit(["src/unrelated.rs"], "side commit (unwatched)")
    fx.g("checkout", "-q", "main")
    fx.banner("LIVE", side)
    nonanc = fx.commit([CERT_DOC], "bind to a non-ancestor with an identical watched tree")
    t.expect_green("v1", "a bind to a non-ancestor with an identical watched tree", repo, base,
                   nonanc, [("federation-wire surface unchanged since the bind",
                             "did not report zero drift since the bind")])
    fx.reset(base)

    # (v2) RED - LIVE bound to a non-ancestor whose watched tree DIFFERS.
    fx.g("checkout", "-q", "-b", "side2", genesis)
    fx.write(mod_rs, "// side wire\n", append=True)
    side2 = fx.commit([mod_rs], "side commit (watched)")
    fx.g("checkout", "-q", "main")
    fx.banner("LIVE", side2)
    evasive = fx.commit([CERT_DOC], "bind to a non-ancestor whose watched tree differs")
    t.expect_red("v2", "a bind to a non-ancestor with a DIFFERENT watched tree (evasion open)",
                 repo, base, evasive, [
        (f"claims LIVE bound to {side2}", "did not name the evasive bound SHA"),
    ])
    fx.reset(base)

    # (w) fail-closed - the doc exists but its STATUS line is unparseable.
    fx.write(CERT_DOC, "# cert\nno banner here\n")
    unparseable = fx.commit([CERT_DOC], "break: banner unparseable")
    t.expect_red("w", "an unparseable STATUS line (not fail-closed)", repo, base, unparseable, [
        ("no parseable STATUS line", "did not name the missing STATUS line"),
    ])
    fx.reset(base)

    # ---- #3556 ruling: the three fixes, a cell each -----------------------

    # (x1) RED - DECOY STATUS line above the real LIVE banner + wire change.
    fx.write(mod_rs, "// mutate\n", append=True)
    fx.banner("LIVE", genesis)
    fx.prepend(CERT_DOC, "> ## STATUS — **VOID as of 2026-01-02** (decoy)")
    decoy_status = fx.commit([mod_rs, CERT_DOC],
                             "violate: decoy STATUS line above the banner + wire change")
    t.expect_red("x1", "a decoy STATUS line above the real banner", repo, base, decoy_status, [
        ("not carry exactly one STATUS banner line", "did not name the duplicated banner"),
    ])
    fx.reset(base)

    # (x2) RED - DECOY on the Binds-to line.
    fx.write(mod_rs, "// mutate\n", append=True)
    wire = fx.commit([mod_rs], "wire change")
    fx.banner("LIVE", genesis)
    fx.prepend(CERT_DOC, f"**Binds to:** `{wire}` (decoy)")
    decoy_binds = fx.commit([CERT_DOC], "violate: decoy Binds-to line above the real one")
    t.expect_red("x2", "a decoy Binds-to line above the real one", repo, base, decoy_binds, [
        ("at most one Binds-to line", "did not name the duplicated Binds-to"),
    ])
    fx.reset(base)

    # (y) RED - the cert doc DELETED in the same change as a wire change.
    fx.write(mod_rs, "// mutate\n", append=True)
    fx.g("rm", "-q", CERT_DOC)
    deleted = fx.commit([mod_rs], "violate: delete the certification + wire change")
    t.expect_red("y", "deleting the cert doc alongside a wire change", repo, base, deleted, [
        ("ABSENT at HEAD (deleted in this change)", "did not name the deletion"),
    ])
    fx.reset(base)

    # (z) GREEN - a PURE REFORMAT of the banner on a docs-only change.
    fx.write(
        CERT_DOC,
        "# Enterprise federation certification (fixture)\n\n"
        f"**Binds  to:**  {genesis.upper()}  (reformatted)\n\n"
        "#  STATUS  -  **LIVE as of 2026-01-01**  (reformatted)\n\nBody prose.\n",
    )
    reformat = fx.commit([CERT_DOC], "docs: reformat the banner")
    t.expect_green("z", "a pure banner reformat (typographic landmine)", repo, base, reformat, [
        (f"banner LIVE bound to {genesis}; federation-wire surface unchanged since the bind",
         "did not parse the reformatted banner to LIVE bound to genesis"),
    ])

    # (z2) RED - the same reformat carried alongside a wire change is INCIDENTAL.
    fx.write(mod_rs, "// mutate\n", append=True)
    reformat_wire = fx.commit([mod_rs], "violate: wire change over the reformatted banner")
    t.expect_red("z2", "reformat + wire change", repo, base, reformat_wire, [
        ("an incidental edit is not a re-issue",
         "did not classify the reformat as incidental (pair unchanged)"),
    ])
    fx.reset(base)

    # ---- #6137: pull_request judged at the merge commit ----------------------
    # History: base (LIVE bound genesis) -> stale_tip (wire change W landed with
    # no re-issue: banner LIVE with drift, the pre-#6121 carrier state). The
    # feature branch is cut at stale_tip. The live base then heals to EXPIRED.
    fx.write(mod_rs, "// W: wire change, banner not re-issued\n", append=True)
    stale_tip = fx.commit([mod_rs], "carrier before the banner fix: wire change, banner still LIVE")
    fx.g("checkout", "-q", "-b", "feature", stale_tip)
    fx.write("src/unrelated.rs", "// feature work\n", append=True)
    feature = fx.commit(["src/unrelated.rs"], "feature: unrelated change on a stale branch")
    fx.g("checkout", "-q", "main")
    fx.banner("EXPIRED", genesis)
    healed_base = fx.commit([CERT_DOC], "carrier banner fix: record EXPIRED (#6121 shape)")
    fx.g("update-ref", "refs/remotes/origin/main", healed_base)
    pr_merge = fx.merge("feature", "Merge feature into main (pull_request merge commit)")

    # (pr1) GREEN at the merge commit; RED if judged at the head in isolation
    #       (the old semantics), proving the two differ on this very history.
    t.expect_green("pr1", "stale-LIVE head banner with base banner EXPIRED, judged at the merge commit",
                   repo, healed_base, feature, [
        ("federation-wire surface unchanged", "did not pass at the merge commit"),
        ("banner STATUS=EXPIRED", "did not read the EXPIRED banner at the merge commit"),
    ], tip=pr_merge)
    t.expect_red("pr1-head", "head-only judgment of the same stale branch (old semantics)", repo,
                 healed_base, feature, [
        ("while its banner still says LIVE", "did not show the stale-LIVE head failure"),
    ])
    pr_env = _gate_env(GITHUB_EVENT_NAME="pull_request", PR_HEAD_SHA=feature,
                       GITHUB_BASE_REF="main", GITHUB_SHA=pr_merge, PATH=os.environ.get("PATH", ""))
    rc, out, err = run_gate(repo, pr_env)
    if rc != 0:
        t.fail("(pr1-gate): pull_request event on the stale branch did not pass end to end:", out + err)

    # (pr3) the payload PR_BASE_SHA is stale (genesis); the LIVE base ref wins.
    captured = io.StringIO()
    with contextlib.redirect_stderr(captured):
        rc, out, err = run_gate(repo, dict(pr_env, PR_BASE_SHA=genesis))
    err = err + captured.getvalue()
    if rc != 0:
        t.fail("(pr3): a stale payload PR_BASE_SHA broke the pull_request verdict:", out + err)
    elif f"unchanged in {healed_base}..{pr_merge}" not in out:
        t.fail("(pr3): the live base was NOT used (range should be base tip..merge commit):", out)
    elif "using the live base" not in err:
        t.fail("(pr3): the stale payload base was not reported:", err)

    # (pr3b) the stale payload base would have given a different range: prove
    #        the verdict text changes if the stale sha were honoured.
    stale_ok, stale_text = check_change(repo, genesis, feature, pr_merge)
    if stale_ok or "is not on the live base" not in stale_text:
        t.fail("(pr3b): a base that does not contain the merge commit's first parent did not fail closed", stale_text)

    # (pr2) the head FLIPS the banner (voiding record + wire change) while the
    #       live base has moved on: detected over merge-base..merge-commit.
    fx.reset(base)
    fx.g("checkout", "-q", "-b", "flip", base)
    fx.write(mod_rs, "// flip branch wire change\n", append=True)
    fx.banner("VOID", genesis)
    flip = fx.commit([mod_rs, CERT_DOC], "flip: wire change + VOID record")
    fx.g("checkout", "-q", "main")
    fx.write("src/unrelated.rs", "// base moved\n", append=True)
    moved_base = fx.commit(["src/unrelated.rs"], "base moves on with an unrelated change")
    fx.g("update-ref", "refs/remotes/origin/main", moved_base)
    flip_merge = fx.merge("flip", "Merge flip into main")
    t.expect_green("pr2", "head that flips the banner (VOID) with the base moved on", repo,
                   moved_base, flip, [
        ("cert doc re-issued/voided", "did not detect the banner flip over merge-base..merge-commit"),
        (f"{moved_base}..{flip_merge}", "did not measure base tip..merge-commit"),
    ], tip=flip_merge)
    # (pr2b) the same wire change WITHOUT the banner flip is still RED there.
    fx.reset(moved_base)
    fx.g("checkout", "-q", "-b", "noflip", base)
    fx.write(mod_rs, "// noflip branch wire change\n", append=True)
    noflip = fx.commit([mod_rs], "noflip: wire change, no cert-doc change")
    fx.g("checkout", "-q", "main")
    noflip_merge = fx.merge("noflip", "Merge noflip into main")
    t.expect_red("pr2b", "wire change without a banner flip over a moved base", repo, moved_base,
                 noflip, [
        (sentence, "did not carry the required §7 expiry sentence"),
        (mod_rs, "did not name the watched path"),
        ("judged at the pull_request merge commit", "did not say it judged the merge commit"),
    ], tip=noflip_merge)

    # (pr5) conductor decision (#6137): the banner is already EXPIRED at the
    #       fork point, the base then gained a wire change, and a stale branch
    #       with no wire change of its own must PASS (the base-side change was
    #       judged when it landed; the PR's own effect is nil).
    fx.reset(base)
    fx.banner("EXPIRED", genesis)
    fork5 = fx.commit([CERT_DOC], "base: banner EXPIRED at the fork point")
    fx.g("checkout", "-q", "-b", "stale5", fork5)
    fx.write("src/unrelated.rs", "// stale5 branch work\n", append=True)
    stale5 = fx.commit(["src/unrelated.rs"], "stale5: unrelated change, no wire change")
    fx.g("checkout", "-q", "main")
    fx.write(mod_rs, "// base-side wire change after the fork\n", append=True)
    base5 = fx.commit([mod_rs], "base gains a wire change after the fork (banner already EXPIRED)")
    fx.g("update-ref", "refs/remotes/origin/main", base5)
    merge5 = fx.merge("stale5", "Merge stale5 into main")
    if mod_rs not in changed_paths(repo, fork5, merge5):
        t.fail("(pr5): control: merge-base..merge-commit no longer sees the base-side wire change")
    t.expect_green("pr5", "stale branch with no wire change over a base that gained one", repo,
                   base5, stale5, [
        (f"unchanged in {base5}..{merge5}", "did not measure base tip..merge-commit"),
    ], tip=merge5)
    rc, out, err = run_gate(repo, dict(pr_env, PR_HEAD_SHA=stale5, GITHUB_SHA=merge5))
    if rc != 0:
        t.fail("(pr5-gate): pull_request event on the stale branch did not pass end to end:", out + err)

    # (pr6) the PR itself adds a wire change, does not flip the banner, base
    #       unchanged: still RED under (A)/(B).
    fx.reset(base)
    fx.g("checkout", "-q", "-b", "wire6", base)
    fx.write(mod_rs, "// wire6 branch wire change\n", append=True)
    wire6 = fx.commit([mod_rs], "wire6: wire change, banner untouched")
    fx.g("checkout", "-q", "main")
    fx.g("update-ref", "refs/remotes/origin/main", base)
    merge6 = fx.merge("wire6", "Merge wire6 into main")
    t.expect_red("pr6", "PR wire change without a banner flip, base unchanged", repo, base, wire6, [
        (sentence, "did not carry the required section 7 expiry sentence"),
        (mod_rs, "did not name the watched path"),
        (f"{base}..{merge6}", "did not measure base tip..merge-commit"),
    ], tip=merge6)

    # (attr, #6174) the PR adds attributes marking src/** binary plus a new
    #       AI_MEMORY_FED_* identifier in an unwatched file. git grep takes
    #       binary-ness from the WORKING TREE (here the merge commit, i.e.
    #       the change under test); the identifier drift must stay RED.
    fx.reset(base)
    fx.g("checkout", "-q", "-b", "attr8", base)
    fx.write(".gitattributes", "src/** binary\n")
    fx.write("src/config.rs", 'pub const Y: &str = "AI_MEMORY_FED_ATTR_KNOB";\n', append=True)
    attr8 = fx.commit([".gitattributes", "src/config.rs"], "attr8: src binary + new identifier")
    fx.g("checkout", "-q", "main")
    fx.g("update-ref", "refs/remotes/origin/main", base)
    merge8 = fx.merge("attr8", "Merge attr8 into main")
    t.expect_red("attr", "identifier add hidden behind head-supplied binary attributes", repo,
                 base, attr8, [
                     ("+ AI_MEMORY_FED_ATTR_KNOB", "did not name the added identifier"),
                     (sentence, "did not carry the required section 7 expiry sentence"),
                 ], tip=merge8)
    t.gate("attr-gate", "pull_request whose head marks src/** binary and adds an identifier",
           repo, _gate_env(GITHUB_EVENT_NAME="pull_request", PR_HEAD_SHA=attr8,
                           GITHUB_BASE_REF="main", GITHUB_SHA=merge8,
                           PATH=os.environ.get("PATH", "")), "+ AI_MEMORY_FED_ATTR_KNOB")
    fx.reset(base)

    # (attr-rm, #6174) the removal direction: the base defines an identifier
    #       only in an unwatched file; the PR marks src/** binary and removes
    #       the definition. The BASE-side scan runs under the head's attributes
    #       too, so it must not regain -I either: the removal must stay RED.
    fx.reset(base)
    fx.g("checkout", "-q", "-b", "rm0", base)
    fx.write("src/attr_rm.rs", 'pub const R: &str = "AI_MEMORY_FED_ATTR_RM_KNOB";\n')
    rm0 = fx.commit(["src/attr_rm.rs"], "rm0: define an identifier in an unwatched file")
    fx.g("checkout", "-q", "-b", "rm9", rm0)
    fx.write(".gitattributes", "src/** binary\n")
    fx.write("src/attr_rm.rs", 'pub const R: &str = "";\n')
    rm9 = fx.commit([".gitattributes", "src/attr_rm.rs"], "rm9: src binary + remove the identifier")
    fx.g("checkout", "-q", "main")
    fx.g("reset", "-q", "--hard", rm0)
    fx.g("update-ref", "refs/remotes/origin/main", rm0)
    merge_rm = fx.merge("rm9", "Merge rm9 into main")
    t.expect_red("attr-rm", "identifier removal hidden behind head-supplied binary attributes",
                 repo, rm0, rm9, [
                     ("- AI_MEMORY_FED_ATTR_RM_KNOB", "did not name the removed identifier"),
                     (sentence, "did not carry the required section 7 expiry sentence"),
                 ], tip=merge_rm)
    t.gate("attr-rm-gate", "pull_request whose head marks src/** binary and removes an identifier",
           repo, _gate_env(GITHUB_EVENT_NAME="pull_request", PR_HEAD_SHA=rm9,
                           GITHUB_BASE_REF="main", GITHUB_SHA=merge_rm,
                           PATH=os.environ.get("PATH", "")), "- AI_MEMORY_FED_ATTR_RM_KNOB")
    fx.reset(base)
    fx.g("update-ref", "refs/remotes/origin/main", base)

    # (mask, #6370) drift compares identifier OCCURRENCES, not just names: the
    #       base defines an identifier in an unwatched file and also mentions it
    #       in a comment elsewhere; the PR removes only the definition. The name
    #       survives in the comment, yet the removal must stay RED.
    fx.reset(base)
    fx.g("checkout", "-q", "-b", "mk0", base)
    fx.write("src/mask_def.rs", 'pub const M: &str = "AI_MEMORY_FED_MASK_KNOB";\n')
    fx.write("src/mask_note.rs", "// the knob AI_MEMORY_FED_MASK_KNOB is read at startup\n")
    fx.banner("EXPIRED", base)  # no live claim, so the mk1 control is judged on drift alone
    mk0 = fx.commit(["src/mask_def.rs", "src/mask_note.rs", CERT_DOC],
                    "mk0: an identifier defined in one unwatched file and mentioned in another")
    fx.g("checkout", "-q", "-b", "mk9", mk0)
    fx.write("src/mask_def.rs", 'pub const M: &str = "";\n')
    mk9 = fx.commit(["src/mask_def.rs"], "mk9: remove the definition, the comment mention stays")
    fx.g("checkout", "-q", "-b", "mk1", mk0)
    fx.write("src/mask_note.rs", "// AI_MEMORY_FED_MASK_KNOB is also described here\n", append=True)
    mk1 = fx.commit(["src/mask_note.rs"], "mk1: one more mention of the same identifier")
    fx.g("checkout", "-q", "main")
    fx.g("reset", "-q", "--hard", mk0)
    fx.g("update-ref", "refs/remotes/origin/main", mk0)
    merge_mk = fx.merge("mk9", "Merge mk9 into main")
    t.expect_red("mask", "definition removed while a comment still names the identifier",
                 repo, mk0, mk9, [
                     ("- AI_MEMORY_FED_MASK_KNOB", "did not name the removed identifier"),
                     ("occurrences in src/ fell 2 -> 1", "did not carry the occurrence-count change"),
                     (sentence, "did not carry the required section 7 expiry sentence"),
                 ], tip=merge_mk)
    t.gate("mask-gate", "pull_request that removes the definition of a still-mentioned identifier",
           repo, _gate_env(GITHUB_EVENT_NAME="pull_request", PR_HEAD_SHA=mk9,
                           GITHUB_BASE_REF="main", GITHUB_SHA=merge_mk,
                           PATH=os.environ.get("PATH", "")), "- AI_MEMORY_FED_MASK_KNOB")
    mask_drift = wire_drift(repo, mk0, mk9)
    if not any(d.startswith("-AI_MEMORY_FED_MASK_KNOB") for d in mask_drift):
        t.fail("(mask-drift): wire_drift did not report the removed definition of a "
               f"still-mentioned identifier: {mask_drift!r}")
    # Control: an extra mention of an existing identifier is not drift (additions
    # are unaffected; only a decrease in occurrences is a removal).
    fx.g("reset", "-q", "--hard", mk0)
    fx.g("update-ref", "refs/remotes/origin/main", mk0)
    merge_mk1 = fx.merge("mk1", "Merge mk1 into main")
    t.expect_green("mask-add", "one more mention of an identifier that already exists",
                   repo, mk0, mk1, tip=merge_mk1)
    fx.reset(base)
    fx.g("update-ref", "refs/remotes/origin/main", base)

    # (mask-offset, #6427) the comparison is keyed on (identifier, trimmed line
    #       text), so a change cannot offset the lost definition line with a
    #       mention added elsewhere. Five offsets, each a removal of the live
    #       definition from mk0 that must stay RED, then the controls.
    kid = "AI_MEMORY_FED_MASK_KNOB"
    def_line = f'pub const M: &str = "{kid}";\n'
    offsets = [
        ("mask-xfile", "definition removed + a mention added in another file",
         {"src/mask_def.rs": 'pub const M: &str = "";\n', "src/mask_new.rs": f"// see {kid}\n"}),
        ("mask-incomment", "definition replaced in place by a comment naming it",
         {"src/mask_def.rs": f"// {kid} was read here\npub const M: &str = \"\";\n"}),
        ("mask-longer", "definition removed + a longer token that contains the name",
         {"src/mask_def.rs": 'pub const M: &str = "";\n', "src/mask_new.rs": f"// NOT{kid}\n"}),
        ("mask-blockcomment", "defining line wrapped in a block comment opened and closed on that line",
         {"src/mask_def.rs": "/* " + def_line.rstrip("\n") + " */\npub const M: &str = \"\";\n"}),
        ("mask-annot", "definition removed + a mention carrying the drift annotation text",
         {"src/mask_def.rs": 'pub const M: &str = "";\n',
          "src/mask_new.rs": f"// -{kid} (occurrences in src/ fell 2 -> 1)\n"}),
        # (#6564) git output is split on LF only. A definition after a `//` comment
        # joined by U+2028 is commented out in Rust (a line comment ends at LF), yet
        # str.splitlines() would give back the original line text.
        ("mask-u2028", "definition behind a // comment joined by U+2028",
         {"src/mask_def.rs": "// note\u2028" + def_line}),
        # (#6564) the key is the whole trimmed line, not the name plus a prefix.
        ("mask-trailing", "value emptied, name moved to a trailing comment on the same line",
         {"src/mask_def.rs": f'pub const M: &str = ""; // {kid}\n'}),
        # Base cases measured on e2c96191e that already went RED; pinned so the
        # keyed comparison cannot lose them.
        ("mask-confusable", "definition reads a confusable name (Cyrillic V)",
         {"src/mask_def.rs": def_line.replace("KNOB", "KNO\u0412")}),
        ("mask-confusable-note", "confusable name + one new mention of the original",
         {"src/mask_def.rs": def_line.replace("KNOB", "KNO\u0412"),
          "src/mask_new.rs": f"// {kid}\n"}),
        ("mask-zwsp", "definition reads the name with a zero-width space inside it",
         {"src/mask_def.rs": def_line.replace("MASK_KNOB", "MASK_\u200bKNOB")}),
        ("mask-crsplit", "definition reads the name split by a carriage return",
         {"src/mask_def.rs": def_line.replace("MASK_KNOB", "MASK_\rKNOB")}),
        ("mask-note-removed", "only the comment mention removed, definition kept",
         {"src/mask_note.rs": "// nothing here\n"}),
    ]
    # The name the report must carry: the removed identifier, or for the
    # look-alike spellings the new truncated name they introduce.
    reported = {"mask-confusable": "+ AI_MEMORY_FED_MASK_KNO",
                "mask-confusable-note": "+ AI_MEMORY_FED_MASK_KNO",
                "mask-zwsp": "+ AI_MEMORY_FED_MASK_", "mask-crsplit": "+ AI_MEMORY_FED_MASK_"}
    gate_labels = {"mask-xfile", "mask-incomment", "mask-longer", "mask-blockcomment",
                   "mask-annot", "mask-u2028", "mask-trailing"}
    for label, desc, edits in offsets:
        fx.g("checkout", "-q", "-B", f"mo-{label}", mk0)
        for rel, text in edits.items():
            fx.write(rel, text)
        head_mo = fx.commit(sorted(edits), f"{label}: {desc}")
        out_mo = t.expect_red(label, desc, repo, mk0, head_mo,
                              [(reported.get(label, f"- {kid}"), "did not name the drifted identifier"),
                               (sentence, "did not carry the required section 7 expiry sentence")])
        if label == "mask-xfile" and "occurrences in src/ fell" in out_mo:
            t.fail(f"(mask-xfile): an offset removal was annotated as a count fall: {out_mo!r}")
        if label in gate_labels:
            # (#6566) the same removal judged end to end on a pull_request merge commit.
            fx.g("checkout", "-q", "main")
            fx.g("reset", "-q", "--hard", mk0)
            fx.g("update-ref", "refs/remotes/origin/main", mk0)
            merge_mo = fx.merge(f"mo-{label}", f"Merge mo-{label} into main")
            t.gate(f"{label}-gate", f"pull_request: {desc}", repo,
                   _gate_env(GITHUB_EVENT_NAME="pull_request", PR_HEAD_SHA=head_mo,
                             GITHUB_BASE_REF="main", GITHUB_SHA=merge_mo,
                             PATH=os.environ.get("PATH", "")), f"- {kid}")
    # (mask-netzero, #6370 F7) the total never falls: the definition is removed and
    #       a note naming the identifier is added in the same change, so the count
    #       is unchanged. Judged on the lines, not the total, it stays RED, both
    #       through the unit and through the pull_request gate.
    fx.g("checkout", "-q", "-B", "mo-netzero", mk0)
    fx.write("src/mask_def.rs", 'pub const M: &str = "";\n')
    fx.write("src/mask_note.rs", f"// {kid} was removed from mask_def.rs\n", append=True)
    nz = fx.commit(["src/mask_def.rs", "src/mask_note.rs"], "mask-netzero: definition out, note in")
    fx.g("checkout", "-q", "main")
    fx.g("reset", "-q", "--hard", mk0)
    fx.g("update-ref", "refs/remotes/origin/main", mk0)
    merge_nz = fx.merge("mo-netzero", "Merge mo-netzero into main")
    t.expect_red("mask-netzero", "definition removed and a note naming it added (count unchanged)",
                 repo, mk0, nz, [
                     (f"- {kid}", "did not name the removed identifier"),
                     ("the total did not fall: 2 -> 2", "did not state that the total held"),
                     (sentence, "did not carry the required section 7 expiry sentence")],
                 tip=merge_nz)
    t.gate("mask-netzero-gate", "pull_request whose net identifier count is unchanged",
           repo, _gate_env(GITHUB_EVENT_NAME="pull_request", PR_HEAD_SHA=nz,
                           GITHUB_BASE_REF="main", GITHUB_SHA=merge_nz,
                           PATH=os.environ.get("PATH", "")), f"- {kid}")
    # (mask-3to2) three occurrences become two: a halving test (after*2 <= before)
    #       would miss it.
    fx.g("checkout", "-q", "-B", "mo-3", mk0)
    fx.write("src/mask_note.rs", f"// {kid} is also described here\n", append=True)
    m3 = fx.commit(["src/mask_note.rs"], "mask-3: a third occurrence")
    fx.g("checkout", "-q", "-B", "mo-3to2", m3)
    fx.write("src/mask_def.rs", 'pub const M: &str = "";\n')
    m32 = fx.commit(["src/mask_def.rs"], "mask-3to2: the definition goes")
    fx.g("update-ref", "refs/remotes/origin/main", m3)
    t.expect_red("mask-3to2", "three occurrences fall to two",
                 repo, m3, m32, [
                     (f"- {kid}", "did not name the removed identifier"),
                     ("occurrences in src/ fell 3 -> 2", "did not carry the 3 -> 2 count change")])
    # (mask-rise) the total goes UP (definition removed, two mentions added): still
    #       RED, and the report must not claim a fall.
    fx.g("update-ref", "refs/remotes/origin/main", mk0)
    fx.g("checkout", "-q", "-B", "mo-rise", mk0)
    fx.write("src/mask_def.rs", 'pub const M: &str = "";\n')
    fx.write("src/mask_new.rs", f"// {kid} one\n// {kid} two\n")
    rise = fx.commit(["src/mask_def.rs", "src/mask_new.rs"], "mask-rise: definition out, two notes in")
    out_rise = t.expect_red("mask-rise", "definition removed while the total rises 2 -> 3",
                            repo, mk0, rise, [
                                (f"- {kid}", "did not name the removed identifier"),
                                ("the total did not fall: 2 -> 3", "did not state that the total rose")])
    if "occurrences in src/ fell" in out_rise:
        t.fail(f"(mask-rise): a rising total was annotated as a fall: {out_rise!r}")
    # (mask-dup) two files carry the same defining line; removing ONE of them is a
    #       loss even though the line text survives in the other (counts are not
    #       collapsed per line).
    fx.g("checkout", "-q", "-B", "mo-dup0", mk0)
    fx.write("src/mask_dup.rs", def_line)
    dup0 = fx.commit(["src/mask_dup.rs"], "mask-dup0: the same defining line in a second file")
    fx.g("update-ref", "refs/remotes/origin/main", dup0)
    fx.g("checkout", "-q", "-B", "mo-dup1", dup0)
    fx.write("src/mask_dup.rs", 'pub const M: &str = "";\n')
    dup1 = fx.commit(["src/mask_dup.rs"], "mask-dup1: one of the two identical definitions goes")
    t.expect_red("mask-dup", "one of two identical defining lines removed",
                 repo, dup0, dup1, [
                     ("occurrences in src/ fell 3 -> 2", "did not carry the 3 -> 2 count change")])
    # (mask-lost2, #6565) two defining lines lost with the total unchanged: the
    #       report counts BOTH lost lines.
    fx.g("update-ref", "refs/remotes/origin/main", mk0)
    fx.g("checkout", "-q", "-B", "mo-lost2", mk0)
    fx.write("src/mask_def.rs", 'pub const M: &str = "";\n')
    fx.write("src/mask_note.rs", "// nothing here\n")
    fx.write("src/mask_new.rs", f"// {kid} one\n// {kid} two\n")
    lost2 = fx.commit(["src/mask_def.rs", "src/mask_note.rs", "src/mask_new.rs"],
                      "mask-lost2: both lines that named the identifier are rewritten")
    t.expect_red("mask-lost2", "two identifier lines rewritten while the total holds",
                 repo, mk0, lost2, [("2 occurrence(s) on lines", "did not count both lost lines")])
    # (mask-trailing-ws) trailing whitespace is not a change to the line text.
    fx.g("checkout", "-q", "-B", "mo-trailing-ws", mk0)
    fx.write("src/mask_def.rs", def_line.rstrip("\n") + "   \n")
    tws = fx.commit(["src/mask_def.rs"], "mask-trailing-ws: trailing blanks on the defining line")
    t.expect_green("mask-trailing-ws", "trailing whitespace added to the defining line",
                   repo, mk0, tws)
    # (mask-dup-add) an identical defining line added in a second file is an extra
    #       mention, not drift.
    fx.g("checkout", "-q", "-B", "mo-dup-add", mk0)
    fx.write("src/mask_dup.rs", def_line)
    dad = fx.commit(["src/mask_dup.rs"], "mask-dup-add: the same defining line in a second file")
    t.expect_green("mask-dup-add", "an identical defining line added in a second file",
                   repo, mk0, dad)
    # Controls: a longer token that merely CONTAINS the prefix is not an identifier,
    # so adding one is GREEN (the left word boundary; letter and underscore prefixes).
    fx.g("update-ref", "refs/remotes/origin/main", mk0)
    for suffix, pre in (("letter", "NOT"), ("underscore", "X_"), ("digit", "9")):
        fx.g("checkout", "-q", "-B", f"mo-longer-{suffix}", mk0)
        fx.write("src/mask_new.rs", f"// {pre}AI_MEMORY_FED_MASK_OTHER_{suffix.upper()}\n")
        lg = fx.commit(["src/mask_new.rs"], f"mask-longer-{suffix}: a longer token is added")
        t.expect_green(f"mask-longer-{suffix}", f"a {suffix}-prefixed longer token is not a new identifier",
                       repo, mk0, lg)
    fx.g("checkout", "-q", "main")
    fx.reset(base)
    fx.g("update-ref", "refs/remotes/origin/main", base)
    # Controls: the defining line moved to another file (re-indented) and an extra
    # mention stay GREEN, so the keyed comparison does not turn refactors red.
    fx.g("checkout", "-q", "-B", "mo-moved", mk0)
    fx.write("src/mask_def.rs", 'pub const M: &str = "";\n')
    fx.write("src/mask_moved.rs", "    " + def_line)
    head_mv = fx.commit(["src/mask_def.rs", "src/mask_moved.rs"], "mask-moved: defining line moved")
    t.expect_green("mask-moved", "the defining line moved to another file", repo, mk0, head_mv)
    fx.reset(base)
    fx.g("update-ref", "refs/remotes/origin/main", base)

    # (value-edit-5-to-6 / value-next-line / trailing-comment-added, #6563, #6626)
    #       the documented split of a value edit. The base reads
    #       `let v = env_or("<id>", 5);`: changing 5 to 6 ON the identifier line
    #       changes that line and is RED; the same change on the line AFTER the
    #       identifier (`let w = env_or(\n "<id>",\n 5);`) leaves the identifier
    #       line byte-identical and is GREEN (the lexical bound). A trailing
    #       comment added to the definition is RED as well, under its own name.
    one = f'let v = env_or("{kid}", 5);\n'
    two = f'let w = env_or(\n    "{kid}",\n    5);\n'
    fx.g("checkout", "-q", "-B", "mo-value-base", mk0)
    fx.write("src/mask_val.rs", one)
    fx.write("src/mask_val2.rs", two)
    vb = fx.commit(["src/mask_val.rs", "src/mask_val2.rs"], "value base: a value on and after the identifier line")
    fx.g("checkout", "-q", "-B", "mo-value-same", vb)
    fx.write("src/mask_val.rs", one.replace("5", "6"))
    vs = fx.commit(["src/mask_val.rs"], "value-edit-5-to-6: the value 5 edited to 6 on the identifier line")
    t.expect_red("value-edit-5-to-6", "the value 5 edited to 6 on the line that carries the identifier",
                 repo, vb, vs, [(f"- {kid}", "did not name the drifted identifier")])
    fx.g("checkout", "-q", "-B", "mo-value-next", vb)
    fx.write("src/mask_val2.rs", two.replace("5", "6"))
    vn = fx.commit(["src/mask_val2.rs"], "value-next-line: the value 5 edited to 6 on the line after the identifier")
    t.expect_green("value-next-line", "the value 5 edited to 6 on the line after the identifier",
                   repo, vb, vn)
    fx.g("checkout", "-q", "-B", "mo-trailing-added", mk0)
    fx.write("src/mask_def.rs", f'pub const M: &str = "{kid}"; // default 6\n')
    tc = fx.commit(["src/mask_def.rs"], "trailing-comment-added: a trailing comment added to the definition")
    t.expect_red("trailing-comment-added", "a trailing comment added to the defining line",
                 repo, mk0, tc, [(f"- {kid}", "did not name the drifted identifier")])
    # (value-edit-ws / value-edit-case / value-trim-nbsp, #6720) the line key is
    #       the line text trimmed of leading and trailing Unicode blanks and
    #       nothing else: an interior-whitespace-only edit and a case-only edit of
    #       the value ON the identifier line are RED, and a trailing U+00A0 is
    #       trimmed like any other blank (GREEN, the re-indent rule). Each pins one
    #       normalisation a refactor of the key must not add (whitespace collapse,
    #       case folding) or drop (Unicode-aware trim).
    ws_line = f'let s = env_or("{kid}", "a  b");\n'
    case_line = f'let c = env_or("{kid}", "on");\n'
    fx.g("checkout", "-q", "-B", "mo-norm-base", mk0)
    fx.write("src/mask_ws.rs", ws_line)
    fx.write("src/mask_case.rs", case_line)
    nb = fx.commit(["src/mask_ws.rs", "src/mask_case.rs"], "norm base: values on the identifier line")
    fx.g("checkout", "-q", "-B", "mo-value-ws", nb)
    fx.write("src/mask_ws.rs", ws_line.replace("a  b", "a b"))
    hw = fx.commit(["src/mask_ws.rs"], "value-edit-ws: two spaces to one inside the value")
    t.expect_red("value-edit-ws", "an interior-whitespace-only edit of the value on the identifier line",
                 repo, nb, hw, [(f"- {kid}", "did not name the drifted identifier")])
    fx.g("checkout", "-q", "-B", "mo-value-case", nb)
    fx.write("src/mask_case.rs", case_line.replace('"on"', '"On"'))
    hc = fx.commit(["src/mask_case.rs"], "value-edit-case: one letter's case changed in the value")
    t.expect_red("value-edit-case", "a case-only edit of the value on the identifier line",
                 repo, nb, hc, [(f"- {kid}", "did not name the drifted identifier")])
    fx.g("checkout", "-q", "-B", "mo-value-nbsp", nb)
    fx.write("src/mask_case.rs", case_line.replace(";\n", ";\u00a0\n"))
    hn = fx.commit(["src/mask_case.rs"], "value-trim-nbsp: a trailing U+00A0 on the identifier line")
    t.expect_green("value-trim-nbsp", "a trailing U+00A0 added to the identifier line (trimmed blank)",
                   repo, nb, hn)
    # (value-copy-bound, #6652) the keyed comparison is a multiset of
    #       (identifier, trimmed line text) over all of src/ without the path, so
    #       a value edited on the identifier line is GREEN while the old line text
    #       still occurs elsewhere under src/: here it survives inside a block
    #       comment next to the edited line. This pins the documented qualifier;
    #       the doc and the behaviour move together (#6560).
    copy_line = f'let q = env_or("{kid}", 7);\n'
    fx.g("checkout", "-q", "-B", "mo-copy-base", mk0)
    fx.write("src/mask_copy.rs", copy_line)
    cb = fx.commit(["src/mask_copy.rs"], "copy base: a value on the identifier line")
    fx.g("checkout", "-q", "-B", "mo-value-copy", cb)
    fx.write("src/mask_copy.rs", copy_line.replace("7", "8") + "/*\n" + copy_line + "*/\n")
    cc = fx.commit(["src/mask_copy.rs"], "value-copy-bound: value edited, old line kept in a block comment")
    t.expect_green("value-copy-bound", "a value edited on the identifier line while the old line "
                   "text stays under src/ inside a block comment (the multiset bound)", repo, cb, cc)
    fx.reset(base)
    fx.g("update-ref", "refs/remotes/origin/main", base)
    # (doc-bound, #6563 / #6561) the docstring, the OK banner and the #6427
    #       changelog fragment say what is detected and name the lexical bound:
    #       none may claim that a block comment AROUND a definition is caught.
    doc_texts = [("module docstring", __doc__ or ""), ("OK banner", SELF_TEST_OK)]
    fragment = REPO_ROOT / "changelog.d" / "6427.fixed.md"
    if fragment.is_file():
        doc_texts.append(("changelog.d/6427.fixed.md", fragment.read_text(encoding="utf-8")))
    for where, text in doc_texts:
        if "block comment around" in text:
            t.fail(f"(doc-bound): the {where} claims a block comment around a definition is "
                   "caught; only a block comment opened and closed on the defining line is")
    if "value-only edit of an existing AI_MEMORY_FED_* identifier in a file outside" in " ".join(
            (__doc__ or "").split()):
        t.fail("(doc-bound): the module docstring still says a value-only edit outside the "
               "path watches is never seen; a value edited on the identifier line is drift")
    # (#6626) the banner may claim a value edit only if a cell edits one.
    for needle in ("(trailing-comment-added)", "(value-edit-5-to-6)", "(value-edit-ws)",
                   "(value-edit-case)", "(value-trim-nbsp)", "(value-copy-bound)"):
        if needle not in SELF_TEST_OK:
            t.fail(f"(doc-bound): the OK banner does not name {needle}; the value-edit claim "
                   "must be pinned by a cell that changes a value (#6626)")
    # (#6652) the RED sentence is conditional and the bound is the multiset one.
    qualifier = "unless the old line text still occurs elsewhere under src/"
    for where, text in doc_texts:
        if where != "OK banner" and qualifier not in " ".join(text.split()):
            t.fail(f"(doc-bound): the {where} does not qualify the value-edit RED claim "
                   f"({qualifier!r} missing, #6652)")
    if "multiset" not in (__doc__ or ""):
        t.fail("(doc-bound): the module docstring does not state the multiset bound "
               "(the line texts are compared over all of src/ without the path, #6652)")
    for needle in ("LEXICAL BOUND", "byte-identical", "#6560"):
        if needle not in (__doc__ or ""):
            t.fail(f"(doc-bound): the module docstring does not state the lexical bound "
                   f"({needle!r} missing)")
    # ---- #6138: merge-commit structure cells ------------------------------
    # main is at `base`; h7 is the PR head, o7 an unrelated branch.
    fx.reset(base)
    fx.g("update-ref", "refs/remotes/origin/main", base)
    fx.g("checkout", "-q", "-b", "h7", base)
    fx.write("src/unrelated.rs", "// h7 PR work\n", append=True)
    head7 = fx.commit(["src/unrelated.rs"], "h7: PR work")
    fx.g("checkout", "-q", "-b", "o7", base)
    fx.write("src/other7.rs", "fn other7() {}\n")
    fx.commit(["src/other7.rs"], "o7: an unrelated branch")
    fx.g("checkout", "-q", "main")
    good7 = fx.merge("h7", "Merge h7 into main")
    fx.reset(base)
    unrel7 = fx.merge("o7", "Merge o7 into main (an unrelated branch, not the PR head)")
    fx.reset(base)
    fx.g("merge", "-q", "--no-ff", "-m", "octopus: h7 and o7 into main", "h7", "o7")
    octo7 = fx.g("rev-parse", "HEAD")
    fx.reset(base)
    env7 = _gate_env(GITHUB_EVENT_NAME="pull_request", PR_HEAD_SHA=head7,
                     GITHUB_BASE_REF="main", GITHUB_SHA=good7, PATH=os.environ.get("PATH", ""))
    t.gate("pr7-ok", "control: a two-parent merge of the live tip and the PR head", repo, env7)
    # R2-F2: the version guard and the is-ancestor error branch are pinned.
    path_before = os.environ.get("PATH")  # #6381: pinned by (shim-path-restore) below
    res = shimmed_cell(t, "gitver", tmp, repo, env7, version="git version 2.29.9")
    if res and (res[0] != 1 or "git >= 2.30 is required" not in res[1] + res[2]):
        t.fail("(gitver): git 2.29.9 did not fail closed with the version guard:", res[1] + res[2])
    res = shimmed_cell(t, "anc-error", tmp, repo, env7, fail="--is-ancestor")
    if res and (res[0] != 1 or "merge-base --is-ancestor exited 128" not in res[1] + res[2]):
        t.fail("(anc-error): an is-ancestor error did not fail closed:", res[1] + res[2])
    res = shimmed_cell(t, "shim-control", tmp, repo, env7)
    if res and res[0] != 0:
        t.fail("(shim-control): the pass-through git shim was REJECTED:", res[1] + res[2])
    # #6178: a scratch path that contains the PATH separator splits the shim
    # entry, so the shim is unreachable and the real git runs; refuse that.
    sep_dir = tmp / f"sep{os.pathsep}dir"
    sep_dir.mkdir()
    try:
        run_gate_shimmed(sep_dir, repo, env7, version="git version 2.29.9")
    except GateError as exc:
        if "PATH separator" not in str(exc):
            t.fail(f"(shim-pathsep): refused for the wrong reason: {exc}")
        elif f"run the self-test from a checkout whose path has no {os.pathsep!r}" not in str(exc):
            t.fail(f"(shim-pathsep): the refusal does not tell the user the remedy: {exc}")
    else:
        t.fail("(shim-pathsep): a scratch path containing the PATH separator was not refused")
    if list(sep_dir.glob("gitshim.*")):
        t.fail("(shim-pathsep-clean): a refused separator path left its shim directory behind")
    # #6380: the call-site wrapper turns a refused shim into exactly one named
    # self-test failure (it must neither swallow the error nor fabricate a verdict).
    rec = FailureRecorder()
    res = shimmed_cell(rec, "shim-pathsep", sep_dir, repo, env7, version="git version 2.29.9")
    if res is not None:
        t.fail(f"(shim-pathsep): shimmed_cell returned a gate verdict for a refused shim: {res!r}")
    if len(rec.messages) != 1:
        t.fail(f"(shim-pathsep): shimmed_cell recorded {len(rec.messages)} failures for a "
               f"refused shim, wanted exactly one: {rec.messages!r}")
    elif ("(shim-pathsep): the git shim could not be installed" not in rec.messages[0]
          or "PATH separator" not in rec.messages[0]):
        t.fail(f"(shim-pathsep): the named failure is wrong: {rec.messages[0]!r}")
    # #6379: a shim that is installed but unreachable for a reason other than the
    # PATH separator (here: not executable, so PATH lookup falls through to the
    # real git) must be refused by name, never leave the gate blamed. Under a
    # checkout path holding the separator the cells above already fail by name.
    if os.pathsep not in str(tmp):
        shims_before = sorted(p.name for p in tmp.glob("gitshim.*"))
        with unittest.mock.patch.object(Path, "chmod", lambda self, mode, *a, **k: None):
            try:
                run_gate_shimmed(tmp, repo, env7, version="git version 2.29.9")
            except GateError as exc:
                if "is not the git on PATH" not in str(exc):
                    t.fail(f"(shim-unreach): refused for the wrong reason: {exc}")
            else:
                t.fail("(shim-unreach): a non-executable git shim (PATH lookup falls through "
                       "to the real git) was not refused")
        if sorted(p.name for p in tmp.glob("gitshim.*")) != shims_before:
            t.fail("(shim-unreach-clean): a refused git shim left its scratch directory behind")
    # #6379: a probe that cannot even start (no git on the probed PATH) is a
    # refusal by name, not a silent pass.
    try:
        _require_shim_reachable(str(tmp / "no-such-dir"), "unused")
    except GateError as exc:
        if "probe failed" not in str(exc):
            t.fail(f"(shim-probe-oserror): refused for the wrong reason: {exc}")
    else:
        t.fail("(shim-probe-oserror): a probe that could not start was treated as reachable")
    # #6428: the shim directory is owned by one try/finally, so ANY exception
    # (not only GateError) raised after it is created must remove it.
    if os.pathsep not in str(tmp):
        shims_before = sorted(p.name for p in tmp.glob("gitshim.*"))
        with unittest.mock.patch.object(sys.modules[__name__], "_require_shim_reachable",
                                        side_effect=RuntimeError("probe blew up")):
            try:
                run_gate_shimmed(tmp, repo, env7, version="git version 2.29.9")
            except RuntimeError:
                pass
            except Exception as exc:  # noqa: BLE001 - a different exception is itself the failure
                t.fail(f"(shim-clean-any-exc): wrong exception type escaped: {exc!r}")
            else:
                t.fail("(shim-clean-any-exc): a probe exception was swallowed")
        if sorted(p.name for p in tmp.glob("gitshim.*")) != shims_before:
            t.fail("(shim-clean-any-exc): a non-GateError exception left the shim scratch "
                   "directory behind")
    # #6428: the probe decodes with errors="replace", so a git that writes bytes
    # that are not UTF-8 is a named refusal, never a UnicodeDecodeError crash.
    if os.pathsep not in str(tmp):
        fake_dir = Path(tempfile.mkdtemp(prefix="fakegit.", dir=str(tmp)))
        try:
            fake = fake_dir / "git"
            fake.write_text(f"#!{sys.executable}\nimport sys\n"
                            "sys.stdout.buffer.write(bytes([0xff, 0xfe, 10]))\n", encoding="utf-8")
            fake.chmod(0o755)
            try:
                _require_shim_reachable(str(fake_dir), "unused")
            except GateError as exc:
                if "is not the git on PATH" not in str(exc):
                    t.fail(f"(shim-probe-decode): refused for the wrong reason: {exc}")
            except Exception as exc:  # noqa: BLE001 - the crash is the failure being pinned
                t.fail(f"(shim-probe-decode): non-UTF-8 probe output crashed the probe: {exc!r}")
            else:
                t.fail("(shim-probe-decode): non-UTF-8 probe output was treated as the marker")
            # #6428: a probe that runs past its timeout is a named refusal; the
            # branch is reached through a real sleeping git and a 1 second budget.
            sleeper = fake_dir / "git"
            sleeper.write_text(f"#!{sys.executable}\nimport time\ntime.sleep(30)\n",
                               encoding="utf-8")
            sleeper.chmod(0o755)
            try:
                _require_shim_reachable(str(fake_dir), "unused", timeout=1)
            except GateError as exc:
                if "probe failed" not in str(exc):
                    t.fail(f"(shim-probe-timeout): refused for the wrong reason: {exc}")
            except Exception as exc:  # noqa: BLE001 - an escaped timeout is the failure
                t.fail(f"(shim-probe-timeout): the probe timeout escaped as {exc!r}")
            else:
                t.fail("(shim-probe-timeout): a probe that timed out was treated as reachable")
        finally:
            shutil.rmtree(fake_dir, ignore_errors=True)
    # #6448: each half of the reachability probe is pinned on its own. The real git
    # fails both halves at once (exit 129, no marker), so only stub gits tell them
    # apart: one exits 0 and prints nothing, one prints the marker and exits 1.
    if os.pathsep not in str(tmp):
        for stub_label, body in (
                ("exit0-no-marker", "pass"),
                ("marker-exit1", "print('probe-nonce')\nsys.exit(1)")):
            stub_dir = Path(tempfile.mkdtemp(prefix="stubgit.", dir=str(tmp)))
            try:
                stub = stub_dir / "git"
                stub.write_text(f"#!{sys.executable}\nimport sys\n{body}\n", encoding="utf-8")
                stub.chmod(0o755)
                try:
                    _require_shim_reachable(str(stub_dir), "probe-nonce")
                except GateError as exc:
                    if "is not the git on PATH" not in str(exc):
                        t.fail(f"(shim-probe-half): {stub_label} refused for the wrong reason: {exc}")
                else:
                    t.fail(f"(shim-probe-half): a git that is {stub_label} was treated as the shim")
            finally:
                shutil.rmtree(stub_dir, ignore_errors=True)
    # #6567 / #6562: the probe answer is a per-run nonce compared exactly, on stdout
    # only. Stub gits that print a loosened form of the nonce (affixed, split by an
    # invalid byte, padded with Unicode whitespace, on stderr, or a different nonce)
    # must each be refused, and a stub that prints exactly the nonce must pass.
    if os.pathsep not in str(tmp):
        nonce = secrets.token_hex(16)
        while nonce == nonce.upper():
            # #6651: the (upper) case needs a nonce with at least one letter.
            nonce = secrets.token_hex(16)
        other = secrets.token_hex(16)
        half = len(nonce) // 2
        exact_cases = (
            ("prefixed", f"sys.stdout.write('x{nonce}\\n')", False),
            ("suffixed", f"sys.stdout.write('{nonce}x\\n')", False),
            ("split-by-ff", f"sys.stdout.buffer.write(b'{nonce[:half]}' + bytes([0xff]) + "
                            f"b'{nonce[half:]}\\n')", False),
            ("u2028-padded", f"sys.stdout.buffer.write('\\u2028{nonce}\\u2028\\n'.encode())", False),
            ("stderr-only", f"sys.stderr.write('{nonce}\\n')", False),
            ("other-nonce", f"sys.stdout.write('{other}\\n')", False),
            ("blank-line-after", f"sys.stdout.write('{nonce}\\n\\n')", False),
            ("crlf", f"sys.stdout.buffer.write(b'{nonce}\\r\\n')", False),
            ("upper", f"sys.stdout.write('{nonce.upper()}\\n')", False),
            ("exact", f"sys.stdout.write('{nonce}\\n')", True))
        for stub_label, body, ok in exact_cases:
            stub_dir = Path(tempfile.mkdtemp(prefix="stubgit.", dir=str(tmp)))
            try:
                stub = stub_dir / "git"
                stub.write_text(f"#!{sys.executable}\nimport sys\n{body}\n", encoding="utf-8")
                stub.chmod(0o755)
                try:
                    _require_shim_reachable(str(stub_dir), marker=nonce)
                except GateError as exc:
                    if ok:
                        t.fail(f"(shim-probe-exact): the exact nonce was refused: {exc}")
                    elif "is not the git on PATH" not in str(exc):
                        t.fail(f"(shim-probe-exact): {stub_label} refused for the wrong reason: {exc}")
                except Exception as exc:  # noqa: BLE001 - an escaped error is the failure
                    t.fail(f"(shim-probe-exact): {stub_label} raised {exc!r}")
                else:
                    if not ok:
                        t.fail(f"(shim-probe-exact): a git whose answer is {stub_label} was "
                               "treated as the shim")
            finally:
                shutil.rmtree(stub_dir, ignore_errors=True)
        # The nonce is drawn per run_gate_shimmed call: two calls must hand the probe
        # two distinct 32-hex-digit markers (a module constant would repeat).
        _shim_nonce_freshness(t, tmp, repo, env7)
        # #6650: the freshness loop must keep the #6380 contract. A shim that cannot
        # be executed (modelled: chmod is a no-op, so the shim keeps its 0o644 mode)
        # is a named (shim-probe-exact) failure, never an escaped exception.
        rec = FailureRecorder()
        try:
            with unittest.mock.patch.object(Path, "chmod", lambda self, *a, **k: None):
                _shim_nonce_freshness(rec, tmp, repo, env7)
        except Exception as exc:  # noqa: BLE001 - an escaped error is the failure
            t.fail(f"(shim-probe-exact-noexec): an unreachable shim escaped the nonce "
                   f"check as {exc!r}")
        else:
            if not rec.messages or not all(m.startswith("(shim-probe-exact)")
                                           for m in rec.messages):
                t.fail(f"(shim-probe-exact-noexec): an unreachable shim was not a named "
                       f"(shim-probe-exact) failure: {rec.messages!r}")
    # #6381: the shim PATH entry is process-global; every shim cell above, on its
    # success path (shim-control), its gate-verdict paths (gitver, anc-error) and
    # its refusal paths (shim-pathsep, shim-unreach), must leave PATH as found.
    if os.environ.get("PATH") != path_before:
        t.fail("(shim-path-restore): PATH was not restored after the git shim cells: "
               f"{path_before!r} -> {os.environ.get('PATH')!r}")
    # Each of the next two cells is rejected by exactly one predicate.
    t.gate("pr7-second", "a two-parent merge whose second parent is an unrelated branch, not "
           "PR_HEAD_SHA", repo, dict(env7, GITHUB_SHA=unrel7), "is not PR_HEAD_SHA")
    t.gate("pr7-octopus", "a three-parent (octopus) merge containing the PR head", repo,
           dict(env7, GITHUB_SHA=octo7), "does not have exactly two parents")
    # The base moves by an unrelated commit after the merge ref was built.
    fx.write("src/main7.rs", "fn main7() {}\n")
    moved7 = fx.commit(["src/main7.rs"], "base moves on with an unrelated commit")
    fx.g("update-ref", "refs/remotes/origin/main", moved7)
    out = t.gate("pr4-moved", "base moved by an unrelated commit (first parent on the base)", repo, env7)
    if f"unchanged in {base}..{good7}" not in out:
        t.fail("(pr4-moved): the range did not start at the merge commit's first parent:", out)
    # Reversed parents: the PR head is the first parent, the base the second.
    fx.g("checkout", "-q", "h7")
    rev7 = fx.merge("main", "Merge main into h7 (reversed parents)")
    fx.g("checkout", "-q", "main")
    t.gate("pr4-reversed", "reversed parents (PR head first)", repo,
           dict(env7, GITHUB_SHA=rev7), "reversed parents")
    # The first parent is not on the live base at all.
    fx.g("update-ref", "refs/remotes/origin/main", side)
    off = t.gate("pr4-offbase", "first parent not on the live base", repo, env7,
                 "is not on the live base")
    if "re-run the job" in off or "push a new commit or sync the branch" not in off:
        t.fail("(pr4-offbase): the remedy must say to push or sync, never re-run:", off)
    if "is not on the live base origin/main (tip " not in off:
        t.fail("(pr4-offbase): the message must name origin/<GITHUB_BASE_REF>:", off)
    for what, sha in (("first parent", fx.g("rev-parse", f"{good7}^1")), ("live tip", side)):
        if off.count(sha) != 1:
            t.fail(f"(pr4-offbase): the {what} sha must be printed exactly once:", off)
    fx.g("update-ref", "refs/remotes/origin/main", base)

    # (pr4) pull_request fail-closed cells; each asserts the reason.
    pr_base_env = _gate_env(GITHUB_EVENT_NAME="pull_request", PR_HEAD_SHA=feature,
                            GITHUB_BASE_REF="main", GITHUB_SHA=pr_merge,
                            PATH=os.environ.get("PATH", ""))
    hex_msg = "is not exactly 40 or 64 hex characters"
    closed = [
        ("no GITHUB_BASE_REF", {k: v for k, v in pr_base_env.items() if k != "GITHUB_BASE_REF"},
         "GITHUB_BASE_REF is unset"),
        ("no PR_HEAD_SHA", {k: v for k, v in pr_base_env.items() if k != "PR_HEAD_SHA"},
         "PR_HEAD_SHA is unset"),
        ("unresolvable PR_HEAD_SHA", dict(pr_base_env, PR_HEAD_SHA="1" * 40),
         "does not resolve to a commit"),
        ("unresolvable merge commit", dict(pr_base_env, GITHUB_SHA="2" * 40),
         "does not resolve to a commit"),
        ("a GITHUB_SHA that is not a two-parent merge", dict(pr_base_env, GITHUB_SHA=base),
         "does not have exactly two parents"),
        ("base ref neither local nor fetchable", dict(pr_base_env, GITHUB_BASE_REF="no-such-branch"),
         "cannot resolve the live base ref"),
        ("option-shaped base ref", dict(pr_base_env, GITHUB_BASE_REF="--upload-pack=x"),
         "is not a plain branch name"),
        ("option-shaped PR_HEAD_SHA", dict(pr_base_env, PR_HEAD_SHA="--upload-pack=x"), hex_msg),
        ("too-short PR_HEAD_SHA", dict(pr_base_env, PR_HEAD_SHA=feature[:6]), hex_msg),
        ("12-char abbreviated PR_HEAD_SHA", dict(pr_base_env, PR_HEAD_SHA=feature[:12]), hex_msg),
        ("40-hex GITHUB_SHA with a trailing newline",
         dict(pr_base_env, GITHUB_SHA=pr_merge + "\n"), hex_msg),
        ("non-hex GITHUB_SHA", dict(pr_base_env, GITHUB_SHA="zz" + pr_merge[2:]), hex_msg),
        ("non-hex PR_BASE_SHA", dict(pr_base_env, PR_BASE_SHA="--oops"), hex_msg),
        ("option-shaped push GITHUB_EVENT_BEFORE",
         {"GITHUB_EVENT_NAME": "push", "GITHUB_EVENT_BEFORE": "--upload-pack=x",
          "GITHUB_SHA": base, "PATH": os.environ.get("PATH", "")}, hex_msg),
    ]
    for why, env, needle in closed:
        t.gate("pr4", f"pull_request with {why}", repo, env, needle)

    # (k) fail-closed - pull_request with nothing set (missing PR head sha / base ref).
    t.gate("k", "pull_request with PR_HEAD_SHA and GITHUB_BASE_REF unset", repo,
           {"GITHUB_EVENT_NAME": "pull_request"}, "PR_HEAD_SHA is unset")

    # ---- #5970 (ported from PR #5871): the event payload is authoritative in CI ----
    push_env = {"GITHUB_EVENT_NAME": "push", "GITHUB_EVENT_BEFORE": base, "GITHUB_SHA": docs,
                "PATH": os.environ.get("PATH", "")}
    refuse = "refused (#5970, fail-closed)"
    t.gate("ci1", "control: a push range from the payload under GitHub Actions", repo,
           dict(push_env, GITHUB_ACTIONS="true"))
    t.gate("ci2", "CERT_EXPIRY_BASE/HEAD overrides under GitHub Actions", repo,
           dict(push_env, GITHUB_ACTIONS="true", CERT_EXPIRY_BASE=base, CERT_EXPIRY_HEAD=docs),
           refuse)
    t.gate("ci3", "an empty CERT_EXPIRY_BASE under GitHub Actions", repo,
           dict(push_env, GITHUB_ACTIONS="true", CERT_EXPIRY_BASE=""), refuse)
    t.gate("ci4", "CERT_EXPIRY_HEAD alone under GitHub Actions", repo,
           dict(push_env, GITHUB_ACTIONS="true", CERT_EXPIRY_HEAD=viol), refuse)
    t.gate("ci5", "an empty event name under GitHub Actions", repo,
           {"GITHUB_ACTIONS": "true", "PATH": os.environ.get("PATH", "")},
           "GITHUB_EVENT_NAME is empty in a CI run")
    t.gate("ci6", "the CERT_EXPIRY_BASE override outside CI (honoured, RED range)", repo,
           {"CERT_EXPIRY_BASE": base, "CERT_EXPIRY_HEAD": viol,
            "PATH": os.environ.get("PATH", "")}, sentence)
    t.gate("ci7", "the CERT_EXPIRY_BASE override outside CI (honoured, docs range)", repo,
           {"CERT_EXPIRY_BASE": base, "CERT_EXPIRY_HEAD": docs,
            "PATH": os.environ.get("PATH", "")})

    # (l) N/A-skip - workflow_dispatch with no override (must not false-fail).
    rc, _o, skip_msg = run_gate(repo, {"GITHUB_EVENT_NAME": "workflow_dispatch"})
    if rc != 0:
        t.fail("(l): workflow_dispatch without CERT_EXPIRY_BASE did not skip")
    if "outside CI" not in skip_msg or "refused under GitHub Actions" not in skip_msg:
        t.fail("(l): the skip message must say the overrides work only outside CI:", skip_msg)

    # (m) N/A-skip - push with all-zero before (new branch / first push).
    rc, _o, _e = run_gate(repo, {"GITHUB_EVENT_NAME": "push", "GITHUB_SHA": base,
                                  "GITHUB_EVENT_BEFORE": "0" * 40})
    if rc != 0:
        t.fail("(m): push with zero before-SHA did not skip")

    # (n) fail-closed - unresolvable range.
    if check_change(repo, "0" * 40, base)[0]:
        t.fail("(n): unresolvable base SHA did not fail closed")

    # (o) GREEN - this PR itself (scripts / workflow / allowlist / CHANGELOG
    #     only; must not trip the gate). Runs against the REAL worktree so a
    #     future edit that accidentally touches the watched surface turns the
    #     self-test red before CI does.
    own_base = ""
    for ref in ("origin/release/v1.0.0", "@{upstream}"):
        if is_commit(REPO_ROOT, ref):
            own_base = git_text(REPO_ROOT, "rev-parse", ref)
            break
    if own_base:
        own_head = git_text(REPO_ROOT, "rev-parse", "HEAD")
        ok, out = check_change(REPO_ROOT, own_base, own_head)
        if not ok:
            t.fail("(o): THIS change trips the cert-expiry gate without touching the cert doc:", out)
    else:
        print("self-test NOTE (o): skipped own-PR check (no origin/release/v1.0.0 "
              "and no @{upstream})", file=sys.stderr)

    if t.failed:
        print("check-cert-expiry self-test: FAIL", file=sys.stderr)
        return 2
    print(SELF_TEST_OK)
    return 0


SELF_TEST_OK = (
    "check-cert-expiry self-test OK: (a) watched-path violation RED with the §7 expiry "
    "sentence; (b) same change + cert-doc GREEN; (c) AI_MEMORY_FED_* identifier-add outside "
    "the path watches RED; (d) identifier-add + cert-doc GREEN; (e) unrelated src/ edit GREEN; "
    "(f) cert-doc-only GREEN; (g) federation_receive.rs RED; (h) federation_signing_check.rs "
    "RED; (h2) nested src/federation/identity/** RED; (i) watched-file rename RED (old path "
    "still named); (j) identifier-rename RED (both names listed); (k) pull_request missing "
    "PR_HEAD_SHA / GITHUB_BASE_REF fail-closed with its reason; (l) workflow_dispatch skip naming the outside-CI-only overrides; (m) push with zero before-SHA skip; "
    "(n) unresolvable range fail-closed; (o) this checkout vs origin/release/v1.0.0 GREEN; "
    "(p) non-ASCII watched path RED (core.quotePath bypass closed); (q) wire change + "
    "incidental cert-doc edit RED (#3556 B); (r) wire change + VOID record GREEN; (s) unrelated "
    "change over a LIVE banner with wire drift since the bind RED (#3556 C, names the bound SHA "
    "and the drift); (t) unrelated change over a VOID banner GREEN; (u) stale LIVE healed by "
    "recording EXPIRED GREEN; (v1) LIVE bound to a non-ancestor with an identical watched tree "
    "GREEN (squash-merge shape, tree diff); (v2) LIVE bound to a non-ancestor whose watched "
    "tree differs RED (the ancestry hatch would have silenced it); (w) unparseable STATUS line "
    "fail-closed; (x1) decoy STATUS line above the banner RED (exactly-one rule); (x2) decoy "
    "Binds-to line RED; (y) cert doc deleted alongside a wire change RED (ABSENT fails closed); "
    "(z) pure banner reformat on a docs-only change GREEN (tolerant parse); (z2) reformat + "
    "wire change RED as incidental, not unparseable; (pr1) #6137 stale-LIVE head banner with "
    "the base EXPIRED GREEN at the merge commit (and RED if judged at the head alone); (pr2) "
    "head that flips the banner detected over base-tip..merge-commit, and a wire change "
    "without the flip RED; (pr3) stale payload PR_BASE_SHA ignored, the live base ref used; "
    "(pr4) pull_request fail-closed, each with its reason, on missing/unresolvable base ref, "
    "head or merge commit and on non-hex, abbreviated or newline-suffixed shas; (pr4-moved) base moved by an unrelated commit "
    "GREEN; (pr4-offbase) first parent not on the base RED naming origin/<base ref>, each sha once, "
    "with the push-or-sync remedy; (gitver) git below 2.30 fail-closed; (anc-error) an is-ancestor "
    "error fail-closed; (shim-pathsep, #6178) a shim scratch path containing the PATH "
    "separator refused with its remedy and reported as exactly one named failure by "
    "shimmed_cell (#6380), so the shim cells never run against the real git; "
    "(shim-unreach, #6379) a non-executable git shim refused and its scratch directory removed "
    "((shim-unreach-clean)); (shim-probe-oserror) a probe that cannot start refused; "
    "(shim-path-restore, #6381) "
    "PATH restored after every shim cell; "
    "(shim-clean-any-exc, #6428) any exception, not only GateError, removes the shim "
    "directory; (shim-probe-decode) non-UTF-8 probe output refused by name; "
    "(shim-probe-timeout) a probe past its timeout refused by name; "
    "(shim-probe-half, #6448) a git that exits 0 without the marker and a git that prints "
    "the marker but exits 1 are each refused; "
    "(shim-probe-exact, #6567/#6562) the probe answer is a per-run nonce compared exactly on "
    "stdout, so an affixed, split, whitespace-padded, stderr-only, wrong-nonce, "
    "blank-line-padded, CR-padded (crlf, #6651) or upper-cased (upper, #6651) answer is "
    "refused; "
    "(shim-probe-exact-noexec, #6650) a shim that cannot be executed in the nonce check is a "
    "named (shim-probe-exact) failure, never a traceback; "
    "(shim-pathsep-clean, #6428) a refused separator path leaves no shim directory; "
    "(attr, attr-gate, #6174) an identifier add hidden behind head-supplied attributes "
    "marking src/** binary RED in check_change and end to end on pull_request; "
    "(attr-rm, attr-rm-gate, #6174) the same for an identifier REMOVAL; "
    "(mask, mask-gate, mask-drift, mask-add, #6370) removing the definition of an identifier "
    "that a comment still names stays RED (occurrence counts, not name sets), while an extra "
    "mention is GREEN; "
    "(mask-xfile-gate, mask-incomment-gate, mask-longer-gate, mask-blockcomment-gate, "
    "mask-annot-gate, mask-u2028-gate, mask-trailing-gate, #6566) the same seven removals "
    "RED end to end on a pull_request merge commit; "
    "(mask-lost2, mask-trailing-ws, mask-dup-add, #6565) two rewritten identifier lines are "
    "both counted in the report, trailing blanks and an identical line added elsewhere are GREEN; "
    "(mask-u2028, mask-trailing, #6564) a definition behind a // comment joined by U+2028 and a "
    "definition replaced by an empty value with the name in a trailing comment stay RED; "
    "(value-edit-5-to-6) the value 5 edited to 6 on the identifier line is RED (#6626); "
    "(value-next-line) the same edit on the line after it is GREEN; "
    "(trailing-comment-added) a trailing comment added to the definition is RED; "
    "(value-edit-ws) an interior-whitespace-only edit of the value on the identifier line is "
    "RED, (value-edit-case) a case-only edit of it is RED, (value-trim-nbsp) a trailing "
    "U+00A0 is a trimmed blank and GREEN (#6720); "
    "(value-copy-bound) a value edited on the identifier line while the old line text "
    "stays under src/ (here in a block comment) is GREEN: the line texts are a multiset over "
    "src/ without the path (#6652); "
    "(doc-bound, #6563) the docstring states the lexical bound; "
    "(mask-xfile, mask-incomment, mask-longer, mask-blockcomment, mask-annot, #6427) a removed "
    "definition offset by a mention in another file, a comment in its place, a longer token, a "
    "block comment opened and closed on the defining line or the drift annotation text stays RED "
    "(a comment opened on a neighbouring line leaves the line unchanged and is the documented "
    "lexical bound, #6560), as do look-alike spellings "
    "(mask-confusable, mask-confusable-note, mask-zwsp, mask-crsplit) and a removed mention "
    "(mask-note-removed), a removal whose total never falls (mask-netzero, mask-netzero-gate) "
    "and a 3 -> 2 fall (mask-3to2), a rising total (mask-rise) and one of two identical definitions (mask-dup) stay RED, a longer token is GREEN (mask-longer-letter, mask-longer-underscore, mask-longer-digit), while a defining line moved to another file is GREEN (mask-moved); "
    "(pr4-reversed) reversed parents RED; (pr5) stale branch without a wire change "
    "over a base that gained one GREEN; (pr6) PR wire change without a banner flip RED; "
    "(pr7) merge with an unrelated branch (second parent is not the PR head) RED and an "
    "octopus merge RED; (ci1-ci7, #5970) the event payload range is authoritative under "
    "GitHub Actions and CERT_EXPIRY_BASE/HEAD overrides are refused there but honoured "
    "outside CI."
)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Enterprise-federation certification section 7 expiry gate.")
    parser.add_argument("--self-test", action="store_true",
                        help="plant-a-violation corpus in a scratch repository")
    args = parser.parse_args(argv)
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
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
