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

TRUSTED MODE (#6140). The required job runs on `pull_request`, so it executes
the pull request's own copy of this script and of its workflow job. The
`pull_request_target` workflow .github/workflows/cert-expiry-trusted.yml checks
out only the BASE commit and runs this (base) copy with
  --trusted --base-ref NAME --head-sha SHA --merge-ref REF [--base-sha SHA]
          [--pr-number N]
and no workflow step fetches pull request content (#6163 precedent). Trusted mode:
  * with --pr-number (strictly `[1-9][0-9]{0,9}`, checked before any git
    call), fetches refs/pull/N/head into refs/remotes/pull/head and
    refs/pull/N/merge into --merge-ref (a
    refs/remotes/ ref) itself and, while that merge ref is missing or its
    second parent is not the head, fetches it again after each of the fixed
    MERGE_REF_SLEEPS; after the last attempt it fails closed with an
    `::error` annotation naming the last fetch error (GitHub builds the test
    merge asynchronously and never for a conflicted pull request, #6176).
    Both destination refs are deleted before the first fetch, and each fetch
    is cut after FETCH_TIMEOUT seconds;
  * reads git objects only (ls-tree / cat-file / diff / grep / log between
    shas); nothing from the head is checked out or executed;
  * takes the range only from its arguments (the process environment,
    CERT_EXPIRY_* and GITHUB_*, is not consulted) and applies the
    pull_request rules above to the merge commit (same fail-closed parentage);
  * prints `GUARD CHANGED: <path>` and fails when a TRUSTED_PATHS entry, or
    the cert-expiry-gate job block of c8-precheck.yml (with that workflow's
    header keys), differs between the merge commit's first parent and the merge
    commit, unless a `Rule-Change-Approved-By: <who>` trailer (the
    claude-md-rule-compare.py mechanism) is in first-parent..head. A trailer
    never waives the section 7 verdict; an approved guard change is also
    printed as a `::warning title=GUARD CHANGED::` annotation;
  * prints `GUARD SHADOW: <workflow> line <n>` and fails (not waivable) when
    any line of any workflow file at the merge commit, headers and the trusted
    workflow included (lines split on every YAML line break; a line break
    other than LF or CRLF is itself refused, #6228), spells the required
    check name or a fragment of it
    outside the two pinned job regions (cert-expiry-gate in c8-precheck.yml,
    cert-expiry-trusted in the trusted workflow, each with one pinned
    `name:`), or when either of those two files uses a YAML construct the
    line scan cannot follow (a second producer of a required context;
    Refs #6177);
  * fails closed on any git read error (a missing object is never "absent")
    and on a blob above MAX_BLOB_BYTES.
In every mode a name the change controls (a path, a workflow file name, a
trailer value, git's stderr) is printed through log_safe(), which escapes
control characters, so it cannot start a workflow-command line (#6175).
In every mode the cert doc is read through its tree entry: a symlink or any
other non-regular entry at its path is refused (fail-closed), never followed.

Usage:
  scripts/check_cert_expiry.py              # against the resolved range
  scripts/check_cert_expiry.py --trusted --base-ref B --head-sha H --merge-ref M
  scripts/check_cert_expiry.py --self-test  # plant-a-violation in a scratch
                                            # repository (never a real branch)

Exit codes: 0 clean / N/A-skip, 1 violation, 2 usage / self-test failure.
"""

import argparse
import contextlib
import errno
import io
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
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


def log_safe(text):
    """TEXT with every control character escaped (#6175): backslash as `\\\\`,
    C0, DEL and C1 as `\\xNN`, U+2028 / U+2029 as `\\uNNNN`. A name the change
    controls (a path, a workflow file name, a trailer value, git's stderr
    echoing one) therefore stays on its own step-log line and can never begin
    a line the Actions runner reads as a workflow command (`::error`, ...)."""
    out = []
    for ch in str(text):
        code = ord(ch)
        if ch == "\\":
            out.append("\\\\")
        elif code < 0x20 or 0x7F <= code <= 0x9F:
            out.append(f"\\x{code:02x}")
        elif code in (0x2028, 0x2029):
            out.append(f"\\u{code:04x}")
        else:
            out.append(ch)
    return "".join(out)


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
        err = log_safe(proc.stderr.decode("utf-8", "replace").strip())
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
        err = log_safe(proc.stderr.decode("utf-8", "replace").strip())
        raise GateError(f"git diff {frm} {to} exited {proc.returncode}: {err}")
    return [p.decode("utf-8", "replace") for p in proc.stdout.split(b"\0") if p]


def extract_fed_ids(repo, tree):
    """Unique AI_MEMORY_FED_* identifiers in src/ at TREE (set of str)."""
    proc = run_git(repo, "grep", "-h", "-I", "-E", FED_ID_PATTERN, tree, "--", "src")
    if proc.returncode == 1:  # no match
        return set()
    if proc.returncode != 0:
        err = log_safe(proc.stderr.decode("utf-8", "replace").strip())
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


REGULAR_MODES = ("100644", "100755")
# Cap on a blob the gate reads whole (the cert doc, the guarded workflow).
MAX_BLOB_BYTES = 2 * 1024 * 1024


def tree_entry(repo, tree, rel):
    """(mode, type, object id) of REL at TREE, or None when absent. Read from
    the object database only (no working tree); a git failure is fail-closed."""
    proc = run_git(repo, "ls-tree", "-z", "--full-tree", "--end-of-options", tree, rel)
    if proc.returncode != 0:
        err = log_safe(proc.stderr.decode("utf-8", "replace").strip())
        raise GateError(f"git ls-tree {tree} {rel} exited {proc.returncode}: {err}")
    for rec in proc.stdout.split(b"\0"):
        meta, sep, name = rec.partition(b"\t")
        if sep and name.decode("utf-8", "replace") == rel:
            fields = meta.decode("ascii", "replace").split(" ")
            if len(fields) != 3:
                raise GateError(f"git ls-tree {tree} {rel}: unparseable entry (fail-closed)")
            return fields[0], fields[1], fields[2]
    return None


def read_blob(repo, oid, rel):
    """Bytes of blob OID (named REL in messages), refused above MAX_BLOB_BYTES."""
    size = git_text(repo, "cat-file", "-s", "--end-of-options", oid)
    if not size.isdigit() or int(size) > MAX_BLOB_BYTES:
        raise GateError(f"{log_safe(rel)} blob {oid} size {size!r} exceeds {MAX_BLOB_BYTES} bytes (fail-closed)")
    proc = run_git(repo, "cat-file", "blob", "--end-of-options", oid)
    if proc.returncode != 0:
        err = log_safe(proc.stderr.decode("utf-8", "replace").strip())
        raise GateError(f"git cat-file blob {oid} ({log_safe(rel)}) exited {proc.returncode}: {err}")
    return proc.stdout


def cert_banner(repo, tree):
    """(STATUS, BINDS) of the cert doc at TREE.

    STATUS: LIVE | VOID | EXPIRED | UNPARSEABLE (doc present, no STATUS line)
    | DUPLICATE (two or more STATUS lines: a decoy above the real banner must
    not be read as the banner) | ABSENT (no doc at TREE). A symlink or any
    other non-regular entry at the cert-doc path raises GateError (#6140).
    BINDS: the lowercase 40-hex bound SHA, "-" when no Binds-to line matches,
    "DUPLICATE" when two or more do.
    """
    entry = tree_entry(repo, tree, CERT_DOC)
    if entry is None:
        return ("ABSENT", "-")
    mode, kind, oid = entry
    if kind != "blob" or mode not in REGULAR_MODES:
        # #6140: a symlink is never followed or read as the banner text.
        raise GateError(
            f"{CERT_DOC} at {tree} is a symlink or other non-regular entry "
            f"(mode {mode} {kind}); refused (fail-closed, #6140)"
        )
    lines = read_blob(repo, oid, CERT_DOC).decode("utf-8", "replace").split("\n")
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
    return log_safe(f"{banner[0]} {banner[1]}")


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
    lines.extend("  " + log_safe(d) for d in drift)
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
        err = log_safe(anc.stderr.decode("utf-8", "replace").strip())
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
        out.extend("  " + log_safe(w) for w in watched)
    if id_changed:
        out.append("AI_MEMORY_FED_* identifiers added/removed/renamed in src/:")
        out.extend("  + " + log_safe(a) for a in added)
        out.extend("  - " + log_safe(r) for r in removed)
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
# --trusted mode (#6140): the pull_request_target companion job
# ---------------------------------------------------------------------------

# Paths whose edit changes what the gate enforces. Editing one needs a
# `Rule-Change-Approved-By:` trailer in the PR's commits (the mechanism and the
# trailer text of scripts/claude-md-rule-compare.py, pinned by the self-test).
TRUSTED_PATHS = ("scripts/check_cert_expiry.py", ".github/workflows/cert-expiry-trusted.yml",
                 "scripts/check-claude-md-size.py")
# The required cert-expiry-gate job block of c8-precheck.yml is guarded too,
# with everything in that workflow outside its other jobs.
TRUSTED_JOB = (".github/workflows/c8-precheck.yml", "cert-expiry-gate")
TRAILER = re.compile(r"^Rule-Change-Approved-By: (\S.*)$", re.MULTILINE)
MERGE_REF_RE = re.compile(r"refs/remotes/[A-Za-z0-9._/-]+")
JOB_KEY_RE = re.compile(r"  ([A-Za-z0-9_.-]+):[ \t]*(?:#.*)?")
JOBS_KEY_RE = re.compile(r"jobs:[ \t]*(?:#.*)?")
# Round 4 (#6228): every line break a YAML parser honours (YAML 1.2 b-break:
# CRLF, CR, LF; YAML 1.1 parsers such as PyYAML also NEL, LS and PS). Workflow
# text is split on all of them, so no line break hides a line from the scan.
YAML_BREAK_RE = re.compile("\r\n|[\r\n\x85\u2028\u2029]")


# Round 5 (#6304): YAML s-white is a space or a tab and nothing else. Python's
# str.strip() also removes NBSP, U+3000 and the other Unicode spaces that YAML
# keeps as content (and FF and VT, which YAML refuses outright), so blank and
# comment tests strip YAML_WHITE only.
YAML_WHITE = " \t"


def yaml_lines(text):
    """The lines of TEXT as a YAML parser sees them (YAML_BREAK_RE)."""
    return YAML_BREAK_RE.split(text)


def _workflow_lines(text):
    """(line number, line, indent, in_jobs, current job key or None) for every
    meaningful line of a workflow file (blank and comment-only lines dropped),
    split on every YAML line break (#6228)."""
    in_jobs, current = False, None
    for number, line in enumerate(yaml_lines(text), 1):
        stripped = line.strip(YAML_WHITE)
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent == 0:
            in_jobs, current = bool(JOBS_KEY_RE.fullmatch(line.rstrip("\r"))), None
        elif in_jobs and indent <= 2:
            m = JOB_KEY_RE.fullmatch(line.rstrip("\r")) if indent == 2 else None
            current = m.group(1) if m else None
        yield number, line, indent, in_jobs, current


def workflow_regions(text, job):
    """(line number, line, guarded) for every meaningful line of a workflow
    file (blank and comment-only lines are dropped). A line is guarded unless
    it is inside a job other than JOB: header keys (on/permissions/env/
    defaults) stay guarded."""
    out = []
    for number, line, _, in_jobs, current in _workflow_lines(text):
        if not in_jobs or current is None or current == job:
            out.append((number, line, True))
        else:
            out.append((number, line, False))
    return out


def guarded_workflow_text(text, job):
    """The part of a workflow file the guard compares: the guarded lines of
    workflow_regions (everything except the jobs other than JOB)."""
    return "\n".join(line for _, line, guarded in workflow_regions(text, job) if guarded)


def guarded_state(repo, tree, rel, job=None):
    """A comparable fingerprint of REL at TREE: absence, a non-regular entry
    (symlink, submodule, tree), the blob id, or for JOB the guarded text."""
    entry = tree_entry(repo, tree, rel)
    if entry is None:
        return "<absent>"
    mode, kind, oid = entry
    if kind != "blob" or mode not in REGULAR_MODES:
        return f"<non-regular {mode} {kind} {oid}>"
    if job is None:
        return f"{mode} {oid}"
    return guarded_workflow_text(read_blob(repo, oid, rel).decode("utf-8", "replace"), job)


def annotation(level, title, message):
    """A GitHub Actions workflow-command line (`::warning title=..::msg`) with
    the message data escaped per the runner's rules (%, CR, LF), so the text
    stays on this one line. TITLE is a fixed literal of this script."""
    data = message.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    return f"::{level} title={title}::{data}"


# The required context the shadow scan protects (c8-precheck.yml cert-expiry-gate).
CERT_CONTEXT = "Enterprise-federation cert-expiry gate (cert §7 / F7)"
WORKFLOW_DIR = ".github/workflows"
# Canonical fragments of CERT_CONTEXT (lowercase, every character except a-z,
# 0-9 and the section sign removed, YAML \x/\u/\U escapes decoded): a scanned
# line run that spells one of them can produce the required check name.
SHADOW_MARKERS = ("certexpiry", "§7f7")
YAML_ESCAPE_RE = re.compile(r"\\(?:x([0-9A-Fa-f]{2})|u([0-9A-Fa-f]{4})|U([0-9A-Fa-f]{8}))")


def _shadow_canon(text):
    def decode(m):
        cp = int(next(g for g in m.groups() if g), 16)
        return chr(cp) if cp <= 0x10FFFF and not 0xD800 <= cp <= 0xDFFF else ""
    return re.sub(r"[^a-z0-9§]", "", YAML_ESCAPE_RE.sub(decode, text).lower())


# Round 3 (code F1, security R2-1): the only regions allowed to spell the
# required check name are the job of each file below whose `name:` is pinned
# (and, in the trusted workflow, two exact header lines). Every other line of
# every workflow file, headers included, is scanned, and both files are
# refused when they use a YAML construct the line scan cannot follow.
TRUSTED_WF_JOB = "cert-expiry-trusted"
TRUSTED_WF_JOB_NAME = "Enterprise-federation cert-expiry gate, trusted base copy (cert §7 / F7)"
TRUSTED_WF_HEADER_LINES = (
    "name: Enterprise-federation cert-expiry gate (trusted base copy)",
    "  group: cert-expiry-trusted-${{ github.event.pull_request.number }}",
)
JOB_NAME_RE = re.compile(r"    name:(?:[ \t]+(.*?))?[ \t]*")
BLOCK_INDICATOR_RE = re.compile(r"[|>]([0-9]?)[+-]?([0-9]?)[ \t]*(?:#.*)?")
SHADOW_NOTE = "(fail-closed, #6140; a trailer does not waive this; Refs #6177)"


def _own_regions():
    """{workflow path: (own job, pinned job name, exempt header lines)}."""
    return {TRUSTED_JOB[0]: (TRUSTED_JOB[1], CERT_CONTEXT, ()),
            TRUSTED_PATHS[1]: (TRUSTED_WF_JOB, TRUSTED_WF_JOB_NAME, TRUSTED_WF_HEADER_LINES)}


def _quoted_end(body, pos):
    """Index just past the quoted scalar starting at POS, or -1 when it does
    not close on this line."""
    quote, i = body[pos], pos + 1
    while i < len(body):
        if quote == '"' and body[i] == "\\":
            i += 2
            continue
        if body[i] == quote:
            if quote == "'" and body[i + 1:i + 2] == "'":
                i += 2
                continue
            return i + 1
        i += 1
    return -1


def _flow_hazard(body, pos):
    """A hazard in the flow collection starting at POS, or None. Node starts
    (after `[`, `{`, `,`, `: ` and `? `) are checked for anchors, aliases,
    tags and quoted keys; the collection must close on this line."""
    depth, i, start = 0, pos, True
    while i < len(body):
        ch = body[i]
        if ch in " \t":
            i += 1
            continue
        if start and ch in "&*!":
            return f"a YAML {'anchor' if ch == '&' else 'alias' if ch == '*' else 'tag'} in a flow collection"
        if ch in "\"'":
            end = _quoted_end(body, i)
            if end < 0:
                return "a quoted scalar spanning lines"
            i, start = end, False
            continue
        if ch == "#" and body[i - 1:i] in (" ", "\t"):
            break
        if ch in "[{":
            depth += 1
        elif ch in "]}":
            depth -= 1
            if depth == 0:
                return None
        start = ch in "[{," or (ch in ":?" and body[i + 1:i + 2] in (" ", ""))
        i += 1
    return "a flow collection spanning lines"


def _node_hazard(body, pos):
    """(hazard or None, block-scalar indicator seen) for the node at POS."""
    rest = body[pos:]
    if not rest or rest.startswith("#"):
        return None, False
    ch = rest[0]
    if ch in "&*!":
        return f"a YAML {'anchor' if ch == '&' else 'alias' if ch == '*' else 'tag'} ({rest.split()[0]})", False
    if ch in "[{":
        return _flow_hazard(body, pos), False
    if ch in "|>":
        m = BLOCK_INDICATOR_RE.fullmatch(rest)
        if m is None or m.group(1) or m.group(2):
            return "a block scalar with an explicit indentation indicator", True
        return None, True
    return None, False


def _yaml_hazards(text):
    """(line number, hazard) for every YAML construct in TEXT that a line scan
    cannot follow: anchors, aliases, tags, merge keys, complex (`?`) or quoted
    keys, quoted scalars or flow collections spanning lines, explicit block
    indentation indicators, document markers and tabs in indentation. Block
    scalar bodies are skipped, so `&&` or `*)` in a `run: |` script is text."""
    out, block_col = [], None
    for number, raw in enumerate(yaml_lines(text), 1):
        body = raw.rstrip("\r")
        stripped = body.strip(YAML_WHITE)
        indent = len(body) - len(body.lstrip(" "))
        if block_col is not None:
            if not stripped or indent > block_col:
                continue
            block_col = None
        if not stripped or stripped.startswith("#"):
            continue
        if body[indent] == "\t":
            out.append((number, "a tab in the indentation"))
            continue
        if indent == 0 and (body.startswith("---") or body.startswith("...")):
            out.append((number, "a YAML document marker"))
            continue
        pos = indent
        while body[pos:pos + 1] == "-" and body[pos + 1:pos + 2] in (" ", ""):
            pos += 1
            while body[pos:pos + 1] == " ":
                pos += 1
        key_col = pos
        if body[pos:pos + 1] == "?" and body[pos + 1:pos + 2] in (" ", ""):
            out.append((number, "a YAML complex key (?)"))
            continue
        hazard, block = _node_hazard(body, pos)
        if hazard is None and not block and body[pos:pos + 1] in ("\"", "'"):
            end = _quoted_end(body, pos)
            if end < 0:
                hazard = "a quoted scalar spanning lines"
            elif body[end:end + 1] == ":":
                hazard = "a quoted mapping key"
        elif hazard is None and not block:
            m = re.match(r"([^\s#\"'][^#]*?):(?:[ \t]+|$)", body[pos:])
            if m:
                if m.group(1).strip() == "<<":
                    hazard = "a YAML merge key (<<)"
                else:
                    value = pos + m.end()
                    hazard, block = _node_hazard(body, value)
                    if hazard is None and not block and body[value:value + 1] in ("\"", "'"):
                        if _quoted_end(body, value) < 0:
                            hazard = "a quoted scalar spanning lines"
        if hazard:
            out.append((number, hazard))
        if block:
            block_col = key_col
    return out


def _own_file_findings(rel, text, job, pinned):
    """GUARD SHADOW lines for the structure of an own file (c8-precheck.yml or
    the trusted workflow): YAML hazards, `jobs:` children that are not plain
    job keys, duplicate jobs, and the own job's single pinned `name:`."""
    found, seen, jobs_lines = [], set(), 0
    name_lines, first_child = [], None
    where = f"{log_safe(rel)}"
    for number, hazard in _yaml_hazards(text):
        found.append(f"GUARD SHADOW: {where} line {number}: {hazard}; a YAML construct the shadow scan "
                     f"cannot follow is refused in this file {SHADOW_NOTE}")
    for number, line, indent, in_jobs, current in _workflow_lines(text):
        body = line.rstrip("\r")
        if indent == 0 and JOBS_KEY_RE.fullmatch(body):
            jobs_lines += 1
            if jobs_lines > 1:
                found.append(f"GUARD SHADOW: {where} line {number}: a second jobs: key {SHADOW_NOTE}")
            continue
        if not in_jobs:
            continue
        if indent <= 2:
            if current is None:
                found.append(f"GUARD SHADOW: {where} line {number}: {log_safe(body.strip())!r} under jobs: is "
                             f"not a plain job key; it may define a job the scan cannot name {SHADOW_NOTE}")
            elif current in seen:
                found.append(f"GUARD SHADOW: {where} line {number}: job '{log_safe(current)}' is defined twice "
                             f"{SHADOW_NOTE}")
            else:
                seen.add(current)
            continue
        if current != job:
            continue
        if first_child is None:
            first_child = (number, indent)
        m = JOB_NAME_RE.fullmatch(body)
        if indent == 4 and m:
            name_lines.append((number, m.group(1) or ""))
    if job not in seen:
        # No own job: nothing in this file is exempt from the line scan, and a
        # missing required job leaves the check unreported (a block, not a pass).
        return found
    if first_child is None or first_child[1] != 4:
        found.append(f"GUARD SHADOW: {where} line {first_child[0] if first_child else '?'}: the {job} job body "
                     f"is not indented by 4 spaces, so its name: line cannot be pinned {SHADOW_NOTE}")
    elif len(name_lines) != 1 or name_lines[0][1] != pinned:
        shown = "; ".join(f"line {n}: {log_safe(v)!r}" for n, v in name_lines) or "none"
        found.append(f"GUARD SHADOW: {where}: job '{job}' must have exactly one name: line, the pinned "
                     f"name '{pinned}' (found {shown}) {SHADOW_NOTE}")
    return found


def _line_break_findings(rel, text):
    """GUARD SHADOW for a YAML line break other than LF or CRLF (a lone CR,
    NEL, LS or PS) anywhere in a workflow file (#6228): a parser starts a new
    line there, so such a break could hide a job from a reader or a scan.
    No legitimate workflow needs one; it is refused, not interpreted."""
    numbers = [n for n, m in enumerate(YAML_BREAK_RE.finditer(text), 1) if m.group() not in ("\n", "\r\n")]
    if not numbers:
        return []
    return [f"GUARD SHADOW: {log_safe(rel)} line {numbers[0]}: a YAML line break other than LF or CRLF (a lone "
            f"CR, NEL, LS or PS; {len(numbers)} in this file) is refused in every workflow file {SHADOW_NOTE}"]


def _listed(items, shown_max=8):
    """The first `shown_max` items joined by ', ', then ', +K more' for the rest."""
    text = ", ".join(str(item) for item in items[:shown_max])
    return text + (f", +{len(items) - shown_max} more" if len(items) > shown_max else "")


def _whitespace_findings(rel, text):
    """GUARD SHADOW for a whitespace character other than space or tab (NBSP,
    U+3000, the other Unicode spaces, FF, VT, ...) anywhere in a workflow file
    (#6304). YAML keeps most of them as content (it refuses FF and VT
    outright) while Python treats them as blank, so a line led by one and then
    `#` would be a comment to the scan and content to a parser. No legitimate
    workflow needs one; it is refused, not interpreted. The message names
    every offending line (the first 8, then a "+K more" marker) and every
    code point (the first 8, then "+K more"; #6556). Line breaks are the
    business of _line_break_findings."""
    seen, numbers = [], []
    for number, line in enumerate(yaml_lines(text), 1):
        hit = False
        for ch in line:
            if ch.isspace() and ch not in YAML_WHITE:
                hit = True
                if ch not in seen:
                    seen.append(ch)
        if hit:
            numbers.append(number)
    if not numbers:
        return []
    where = f"{'line' if len(numbers) == 1 else 'lines'} {_listed(numbers)} ({len(numbers)} in this file)"
    shown = _listed([f"U+{ord(c):04X}" for c in seen])
    return [f"GUARD SHADOW: {log_safe(rel)} {where}: a whitespace character other than space or tab "
            f"({shown}) is refused in every workflow file {SHADOW_NOTE}"]


def _scan_workflow(rel, text, own):
    """GUARD SHADOW lines for REL: every meaningful line outside the own job
    region (and the own exact header lines) is scanned; consecutive scanned
    lines are joined, so a folded or escaped scalar is still caught. One line
    per job region (or the header) that spells the required check name."""
    job, _, header = own if own else (None, None, ())
    found, reported, window = [], set(), ""
    for number, line, _, in_jobs, current in _workflow_lines(text):
        if own and ((in_jobs and current == job) or (not in_jobs and line.rstrip("\r") in header)):
            window = ""
            continue
        region = f"job '{log_safe(current)}'" if current else ("jobs: block" if in_jobs else "workflow header")
        window += _shadow_canon(line)
        if any(m in window for m in SHADOW_MARKERS):
            window = ""
            if region not in reported:
                reported.add(region)
                found.append(
                    f"GUARD SHADOW: {log_safe(rel)} line {number} ({region}): names the required check "
                    f"'{CERT_CONTEXT}' (or a fragment of it) outside the pinned job regions; a second producer "
                    f"of a required context can satisfy it with an always-green job {SHADOW_NOTE}")
            continue
        window = window[-16:]
    return found


def shadow_check(repo, merge):
    """(ok, lines): no job outside the pinned own job regions (the
    cert-expiry-gate job of c8-precheck.yml, the cert-expiry-trusted job of
    the trusted workflow) can produce the required check name at MERGE
    (#6140 rounds 2 to 4). Every workflow blob in .github/workflows is read
    from git objects and every line of it, split on every YAML line break, is
    scanned, headers included; a line break other than LF or CRLF (#6228) and a
    whitespace character other than space or tab (#6304) are refused in every
    workflow file;
    both own files must keep a single pinned `name:` in their job and use no
    YAML construct (anchor, alias, tag, quoted or flow job key, ...) the scan
    cannot follow. Not waivable by a trailer: a legitimate change never needs
    a second producer of a required context. A name built at run time from a
    `${{ }}` expression is outside a text scan (Refs #6177)."""
    entry = tree_entry(repo, merge, WORKFLOW_DIR)
    if entry is None:
        return True, [f"{PREFIX}: shadow scan — no {WORKFLOW_DIR} at {merge}"]
    if entry[1] != "tree":
        return False, [f"GUARD SHADOW: {WORKFLOW_DIR} at {merge} is not a directory "
                       f"(mode {entry[0]} {entry[1]}); refused (fail-closed, #6140)"]
    proc = run_git(repo, "ls-tree", "-z", "--full-tree", "--end-of-options", merge, WORKFLOW_DIR + "/")
    if proc.returncode != 0:
        err = log_safe(proc.stderr.decode("utf-8", "replace").strip())
        raise GateError(f"git ls-tree {merge} {WORKFLOW_DIR}/ exited {proc.returncode}: {err}")
    owns = _own_regions()
    found, scanned = [], 0
    for rec in proc.stdout.split(b"\0"):
        meta, sep, name = rec.partition(b"\t")
        rel = name.decode("utf-8", "replace")
        if not sep or not rel.lower().endswith((".yml", ".yaml")):
            continue
        fields = meta.decode("ascii", "replace").split(" ")
        if len(fields) != 3:
            raise GateError(f"git ls-tree {merge} {WORKFLOW_DIR}/: unparseable entry (fail-closed)")
        mode, kind, oid = fields
        if kind == "tree":
            continue
        if kind != "blob" or mode not in REGULAR_MODES:
            found.append(f"GUARD SHADOW: {log_safe(rel)}: a symlink or other non-regular workflow entry "
                         f"(mode {mode} {kind}); refused (fail-closed, #6140)")
            continue
        scanned += 1
        text = read_blob(repo, oid, rel).decode("utf-8", "replace")
        found.extend(_line_break_findings(rel, text))
        found.extend(_whitespace_findings(rel, text))
        own = owns.get(rel)
        if own:
            found.extend(_own_file_findings(rel, text, own[0], own[1]))
        found.extend(_scan_workflow(rel, text, own))
    if found:
        return False, found
    return True, [f"{PREFIX}: shadow scan — {scanned} workflow file(s) at {merge}: no second producer "
                  f"of '{CERT_CONTEXT}'"]


def guard_check(repo, first, head, merge):
    """(ok, lines): trusted paths changed between the merge commit's first
    parent and the merge commit, and the approval trailers in first..head."""
    changed = [rel for rel in TRUSTED_PATHS
               if guarded_state(repo, first, rel) != guarded_state(repo, merge, rel)]
    rel, job = TRUSTED_JOB
    if guarded_state(repo, first, rel, job) != guarded_state(repo, merge, rel, job):
        changed.append(f"{rel} ({job} job)")
    if not changed:
        return True, [f"{PREFIX}: trusted guard — no trusted gate path changed in {first}..{merge}"]
    log = git_text(repo, "log", "--format=%B%x00", "--end-of-options", f"{first}..{head}")
    who = [log_safe(m.group(1).strip()) for m in TRAILER.finditer(log)]
    lines = [f"GUARD CHANGED: {c} (changes what the cert-expiry gate enforces)" for c in changed]
    if who:
        lines.append(f"{PREFIX}: approval trailer(s): {'; '.join(who)} (the §7 verdict is not waived)")
        # Round 2 (F5 of the security review): the approval is self-asserted, so it
        # is surfaced on the checks page, not only in the step log.
        lines.extend(annotation(
            "warning", "GUARD CHANGED",
            f"{c} changed in {first}..{merge}; approved by trailer: {'; '.join(who)} (tamper-evidence: "
            "review and the sole merger confirm; the §7 verdict is not waived)") for c in changed)
        return True, lines
    lines.append(
        f"RESULT: FAIL — a trusted cert-expiry gate path changed without a "
        f"'Rule-Change-Approved-By: <who>' trailer in {first}..{head} (fail-closed, #6140)"
    )
    return False, lines


def resolve_merge_ref(repo, ref):
    """Full sha of the pull_request merge commit named by REF (a 40/64-hex sha
    or a refs/remotes/... ref the workflow fetched); fail-closed otherwise."""
    if not (ENV_SHA_RE.fullmatch(ref) or (MERGE_REF_RE.fullmatch(ref) and ".." not in ref)):
        raise GateError(
            f"--merge-ref {ref!r} is not a 40/64-hex sha or a refs/remotes/ ref (fail-closed)"
        )
    proc = run_git(repo, "rev-parse", "--verify", "--quiet", "--end-of-options", ref + "^{commit}")
    if proc.returncode != 0:
        raise GateError(f"--merge-ref {ref} does not resolve to a commit (fail-closed)")
    return proc.stdout.decode().strip()


# #6176: pull_request_target does not wait for GitHub to (re)build the test
# merge, and a conflicted pull request has none. With --pr-number the gate
# fetches refs/pull/<N>/merge itself and re-fetches a stale or missing one a
# FIXED number of times with FIXED sleeps (len + 1 attempts, 65 s at most),
# then fails closed with an ::error annotation. A stale merge commit is never
# judged: it could only produce a false RED, never a false GREEN.
MERGE_REF_SLEEPS = (5, 10, 20, 30)
PR_NUMBER_RE = re.compile(r"[1-9][0-9]{0,9}", re.ASCII)
# #6163 precedent: no workflow step fetches pull request content; with
# --pr-number this base copy fetches the head as git objects into this ref.
HEAD_FETCH_REF = "refs/remotes/pull/head"
_sleep = time.sleep  # self-test seam: the cells record the backoff instead of sleeping
# Round 3 (code F3, security R2-4): every fetch is cut after FETCH_TIMEOUT
# seconds. Worst case: (1 head + 5 merge fetches) x 45 s + 65 s of sleeps =
# 335 s, inside the 600 s (timeout-minutes: 10) trusted job with room for the
# checkout and the self-test step. The other git calls read local objects.
FETCH_TIMEOUT = 45


class MergeRefError(GateError):
    """#6176: the test merge never became current; reported as an ::error."""


def _merge_ref_state(repo, merge_ref, head):
    """None when MERGE_REF names a two-parent commit whose second parent is
    HEAD; otherwise a short reason (missing or stale)."""
    proc = run_git(repo, "rev-list", "--parents", "-n", "1", "--end-of-options", merge_ref + "^{commit}")
    if proc.returncode != 0:
        return "missing (no merge commit was fetched)"
    shas = proc.stdout.decode("utf-8", "replace").split()
    if len(shas) != 3 or shas[2].lower() != head.lower():
        return f"stale (merge commit {shas[0][:12] if shas else '?'} does not have the head as its second parent)"
    return None


def fetch_merge_ref(repo, pr_number, merge_ref, head):
    """Fetch refs/pull/<PR>/head into HEAD_FETCH_REF once and refs/pull/<PR>/merge
    into MERGE_REF until it is current for HEAD, with the fixed
    MERGE_REF_SLEEPS backoff (objects only, nothing checked out; a fixed
    argument list, never a shell). PR_NUMBER is validated before any git call;
    both destination refs are deleted before the first fetch, and each fetch
    is cut after FETCH_TIMEOUT seconds. Raises MergeRefError (an ::error
    annotation) on a failed head fetch and after the last merge attempt,
    naming the last fetch error (fail-closed)."""
    if not PR_NUMBER_RE.fullmatch(pr_number):
        raise GateError(f"--pr-number {pr_number!r} is not a decimal pull request number (fail-closed)")
    if not (MERGE_REF_RE.fullmatch(merge_ref) and ".." not in merge_ref):
        raise GateError(f"--merge-ref {merge_ref!r} must be a refs/remotes/ ref when --pr-number is given "
                        "(the gate fetches into it; fail-closed)")
    # Round 3 (security R2-5): a destination ref an earlier run left behind is
    # deleted first, so only what this run fetched is ever judged.
    for ref in (HEAD_FETCH_REF, merge_ref):
        proc = run_git(repo, "update-ref", "-d", ref)
        if proc.returncode != 0:
            err = log_safe(proc.stderr.decode("utf-8", "replace").strip())
            raise GateError(f"git update-ref -d {ref} exited {proc.returncode}: {err} (fail-closed)")
    err = _fetch(repo, f"+refs/pull/{pr_number}/head:{HEAD_FETCH_REF}")
    if err:
        raise MergeRefError(f"git fetch of refs/pull/{pr_number}/head failed: {err} (fail-closed)")
    attempts = len(MERGE_REF_SLEEPS) + 1
    reason, last_error = "missing", ""
    for attempt in range(attempts):
        err = _fetch(repo, f"+refs/pull/{pr_number}/merge:{merge_ref}")
        last_error = err or last_error
        reason = _merge_ref_state(repo, merge_ref, head)
        if reason is None:
            return
        if attempt < len(MERGE_REF_SLEEPS):
            _sleep(MERGE_REF_SLEEPS[attempt])
    detail = f"; last fetch error: {last_error}" if last_error else ""
    raise MergeRefError(
        f"refs/pull/{pr_number}/merge is {reason} after {attempts} fetch attempts "
        f"(sleeps {', '.join(str(n) for n in MERGE_REF_SLEEPS)} s){detail}. GitHub had not built a current test "
        "merge for this head; a pull request with a merge conflict has none. Resolve any conflict, or push or "
        "sync the branch, then re-run this job (fail-closed)"
    )


def _fetch(repo, refspec):
    """Fetch REFSPEC from origin (objects only, a fixed argument list, cut
    after FETCH_TIMEOUT seconds); "" on success, else the log-safe error."""
    try:
        proc = run_git(repo, "fetch", "--no-tags", "--no-recurse-submodules", "--quiet", "--end-of-options",
                       "origin", refspec, timeout=FETCH_TIMEOUT)
    except GateError as exc:
        return log_safe(str(exc))
    if proc.returncode != 0:
        return f"exited {proc.returncode}: {log_safe(proc.stderr.decode('utf-8', 'replace').strip())}"
    return ""


def run_trusted(repo, base_ref, head, merge_ref, base_sha="", pr_number=None):
    """--trusted: judge the pull_request merge commit with THIS (base) copy of
    the gate, reading git objects only, and require the approval trailer when
    a trusted path changed. The range comes only from the arguments: the
    process environment (CERT_EXPIRY_*, GITHUB_*) is not consulted.
    Returns (rc, stdout_text, stderr_text)."""
    try:
        require_git_version(repo)
        if not ENV_SHA_RE.fullmatch(head):
            raise GateError(f"--head-sha {head!r} is not exactly 40 or 64 hex characters (fail-closed)")
        if base_sha and not ENV_SHA_RE.fullmatch(base_sha):
            raise GateError(f"--base-sha {base_sha!r} is not exactly 40 or 64 hex characters (fail-closed)")
        if pr_number is not None:
            fetch_merge_ref(repo, pr_number, merge_ref, head)
        merge = resolve_merge_ref(repo, merge_ref)
    except MergeRefError as exc:
        return 1, "", "\n".join((annotation("error", "cert-expiry trusted", str(exc)), f"{PREFIX}: ERROR — {exc}"))
    except GateError as exc:
        return 1, "", f"{PREFIX}: ERROR — {exc}"
    env = {"GITHUB_EVENT_NAME": "pull_request", "PR_HEAD_SHA": head,
           "GITHUB_BASE_REF": base_ref, "GITHUB_SHA": merge}
    if base_sha:
        env["PR_BASE_SHA"] = base_sha
    rc, out, err = run_gate(repo, env)
    outs, errs = [out] if out else [], [err] if err else []
    try:
        live = resolve_live_base(repo, base_ref)
        first = pr_base_tip(repo, live, head, merge, f"origin/{base_ref}")
        ok, lines = guard_check(repo, first, head, merge)
        shadow_ok, shadow_lines = shadow_check(repo, merge)
        ok, lines = ok and shadow_ok, lines + shadow_lines
    except GateError as exc:
        suffix = "" if str(exc).endswith("(fail-closed)") else " (fail-closed)"
        ok, lines = False, [f"{PREFIX}: ERROR — trusted guard: {exc}{suffix}"]
    (outs if ok else errs).append("\n".join(lines))
    rc = 0 if rc == 0 and ok else 1
    return rc, "\n".join(outs), "\n".join(errs)


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
            err = log_safe(proc.stderr.decode("utf-8", "replace").strip())
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


GIT_SHIM = """#!{python} -I
import os, sys
real, argv = {real!r}, sys.argv[1:]
if argv == ["--shim-isolation-probe"]:
    try:
        import gitshim_canary_6145
        planted = True
    except ImportError:
        planted = False
    print(sys.flags.isolated, planted)
    sys.exit(0)
if "--version" in argv and {version!r}:
    print({version!r})
    sys.exit(0)
if {fail!r} and {fail!r} in argv:
    sys.stderr.write("fatal: shim refuses " + {fail!r} + chr(10))
    sys.exit(128)
os.execv(real, [real] + argv)
"""


SHEBANG_MAX = 255  # Linux truncates the interpreter line at 256 bytes (newline included)
MKDTEMP_NAME_LEN = len("gitshim-long.") + 8  # tempfile.mkdtemp appends 8 random characters
# Longest absolute scratch path under which the 255-byte boundary cell still fits:
# 255 - '#!' - ' -I' - '/gitshim-long.XXXXXXXX' - the pad's 1 byte - a 1-byte file name.
SCRATCH_PATH_LIMIT = 255 - len("#!") - len(" -I") - (1 + MKDTEMP_NAME_LEN) - 2


def write_git_shim(shim_dir, real, version="", fail="", interpreter=None):
    """Write the executable `git` PATH shim into shim_dir (#6145: its interpreter
    line is `python3 -I`, like the gate itself in c8-precheck.yml, so the shim's
    own directory is never on its sys.path). Fails closed with GateError when the
    interpreter line cannot carry `-I` intact: whitespace or a NUL byte in the
    interpreter path splits it, a path that is not valid UTF-8 cannot be written, and
    a line over SHEBANG_MAX (255) bytes is truncated by the kernel, which silently
    drops `-I` (a 255-byte line is accepted, a 256-byte line refused).

    Self-test limit (#6145 R5-F3): the `shim-interpreter` cell builds 255/256-byte
    interpreter lines under its scratch dir, so that dir's absolute path must be at
    most SCRATCH_PATH_LIMIT (226) bytes, i.e. the checkout path at most 184 bytes
    (CI uses 44); the checkout-depth cell pins that no other cell needs more (R8-F1).
    A deeper checkout fails the cell with a message naming both
    lengths; it is a property of the environment, not a defect in the gate."""
    python = sys.executable if interpreter is None else str(interpreter)
    line = f"#!{python} -I"
    if not python or "\x00" in python or any(ch.isspace() for ch in python):
        raise GateError(f"the shim interpreter path {python!r} is empty or contains "
                        "whitespace or a NUL byte; its '-I' flag would not survive the shebang")
    try:
        line_bytes = len(line.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise GateError(f"the shim interpreter path {python!r} is not valid UTF-8 ({exc.reason}); "
                        "the shim is written as UTF-8, so its '-I' flag cannot be guaranteed") from exc
    if line_bytes > SHEBANG_MAX:
        raise GateError(f"the shim interpreter line is {line_bytes} bytes, over "
                        f"{SHEBANG_MAX}; the kernel would truncate it and drop '-I'")
    shim = shim_dir / "git"
    shim.write_text(GIT_SHIM.format(python=python, real=real, version=version,
                                    fail=fail), encoding="utf-8")
    shim.chmod(0o755)
    return shim


def shim_interpreter_violation(tmp):
    """None when write_git_shim refuses every unsafe interpreter path and accepts
    the longest safe one (#6145 S-F1), else a description. The boundary is sized to
    the LITERAL 255/256 byte lines the kernel allows/truncates, never to SHEBANG_MAX,
    so changing that constant to 256 fails here (#6145 R3-F1). Needs the scratch dir's
    absolute path to be at most SCRATCH_PATH_LIMIT (226) bytes, i.e. a checkout path
    of at most 184 bytes; deeper, it reports the lengths instead of building (R5-F3)."""
    fixed = len("#!") + len(" -I")
    deep = None
    try:
        deep = Path(tempfile.mkdtemp(prefix="gitshim-long.", dir=str(tmp)))
        pad = 255 - fixed - len(os.fsencode(str(deep))) - 1
        if pad < 1:
            have = len(os.fsencode(str(tmp)))
            return (f"the scratch path is too deep to build the boundary cases (pad {pad}): "
                    f"the scratch path is {have} bytes but the 255-byte shebang boundary cell "
                    f"needs it at most {SCRATCH_PATH_LIMIT} bytes (checkout path at most "
                    f"{SCRATCH_PATH_LIMIT - have + len(os.fsencode(str(REPO_ROOT)))} bytes); "
                    "run the self-test from a shallower checkout")
        long_dir = deep / ("d" * 200)
        long_dir.mkdir()
        too_long = long_dir / ("p" * 60)
        too_long.symlink_to(sys.executable)
        spaced = deep / "with space" / "python3"
        longest_ok = deep / ("q" * pad)
        one_over = deep / ("q" * (pad + 1))
        for want, interp in ((255, longest_ok), (256, one_over)):
            got = len(os.fsencode(f"#!{interp} -I"))
            if got != want:
                return f"the {want}-byte boundary case is {got} bytes"
        non_utf8 = deep / "py\udcff"
        cases = [("an over-long interpreter path", too_long, True),
                 ("an interpreter path with whitespace", spaced, True),
                 ("the longest in-limit interpreter path", longest_ok, False),
                 ("a 256-byte interpreter line", one_over, True),
                 ("a non-UTF-8 (surrogate-escaped) interpreter path", non_utf8, True),
                 ("an interpreter path with a NUL byte", deep / "py\x00x", True)]
        for label, interp, must_raise in cases:
            try:
                write_git_shim(deep, "git", interpreter=interp)
            except GateError:
                if not must_raise:
                    return f"{label} was refused"
                continue
            except Exception as exc:  # noqa: BLE001 - report any non-GateError as a violation
                return f"{label} raised {type(exc).__name__}, not GateError: {exc}"
            if must_raise:
                return f"{label} was accepted (the kernel would drop '-I')"
        return None
    except OSError as exc:
        return f"could not build the boundary cases: {exc}"
    finally:
        if deep is not None:
            shutil.rmtree(deep, ignore_errors=True)



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


def deep_scratch(tmp, target_len):
    """A scratch directory whose absolute path is EXACTLY target_len bytes, built
    with dir_fd so no single syscall sees a path over PATH_MAX (#6145 R3-F2, R4-F2).
    Returns (base, deepest); on any failure removes base and raises OSError (R4-F3)."""
    base = Path(tempfile.mkdtemp(prefix="gitshim-deep.", dir=str(tmp)))
    fds = []
    try:
        cur, cur_len = base, len(os.fsencode(str(base)))
        fds.append(os.open(str(base), os.O_RDONLY))
        while cur_len < target_len:
            room = target_len - cur_len
            step = min(200, room - 1)
            if room - step - 1 == 1:
                step -= 1  # a final component needs 2 bytes ('/' + 1 char)
            if step < 1:
                raise OSError(errno.ENAMETOOLONG,
                              f"cannot land on exactly {target_len} bytes from {cur_len}")
            name = "d" * step
            os.mkdir(name, dir_fd=fds[-1])
            fds.append(os.open(name, os.O_RDONLY, dir_fd=fds[-1]))
            cur, cur_len = cur / name, cur_len + 1 + step
        if cur_len != target_len:
            raise OSError(errno.ENAMETOOLONG,
                          f"the scratch base is {cur_len} bytes, over the {target_len}-byte target")
        return base, cur
    except BaseException:
        shutil.rmtree(base, ignore_errors=True)
        raise
    finally:
        for fd in fds:
            os.close(fd)


def shim_boundary_robustness_violation(tmp):
    """None when shim_interpreter_violation reports (never raises) on a scratch dir
    that is missing or sits just under PATH_MAX (#6145 R3-F2), else a description.
    The near-PATH_MAX path is sized from the platform's PATH_MAX (R4-F1) and the cell
    asserts the 200-byte directory build would overflow it (R4-F2), so moving the
    'too deep' check after the build turns this cell red."""
    missing = shim_interpreter_violation(tmp / "no-such-scratch-6145")
    if missing is None or not missing.startswith("could not build the boundary cases"):
        return f"a missing scratch dir gave {missing!r}, not a 'could not build' violation"
    limit = path_max(tmp)
    target = limit - 1 - (MKDTEMP_NAME_LEN + 1) - 1
    try:
        base, near_max = deep_scratch(tmp, target)
    except OSError as exc:
        return f"could not build the near-PATH_MAX scratch: {exc}"
    try:
        if len(os.fsencode(str(near_max))) + MKDTEMP_NAME_LEN + 1 + 201 < limit:
            return (f"the near-PATH_MAX scratch ({target} bytes) is too short for the 200-byte "
                    f"build to overflow PATH_MAX {limit}")
        try:
            deep = shim_interpreter_violation(near_max)
        except OSError as exc:
            return f"a near-PATH_MAX scratch dir raised {type(exc).__name__}: {exc}"
        if deep is None or not deep.startswith("the scratch path is too deep"):
            return f"a near-PATH_MAX scratch dir gave {deep!r}, not a 'too deep' violation"
        left = [p.name for p in near_max.iterdir()] if near_max.is_dir() else []
        if left:
            return f"a near-PATH_MAX scratch dir was left with {left!r}"
    finally:
        shutil.rmtree(base, ignore_errors=True)
    return None


def deep_scratch_base_len(tmp):
    """Length of the shortest path deep_scratch(tmp, ...) can return: the scratch dir,
    a separator, the `gitshim-deep.` prefix and the 8-byte mkdtemp suffix (#6145 R7-F2)."""
    return len(os.fsencode(str(tmp))) + 1 + len("gitshim-deep.") + 8


def deep_scratch_violation(tmp):
    """None when deep_scratch lands on the exact length, cleans up after itself on
    failure and the robustness cell turns a build failure into a named violation
    (#6145 R4-F1/F2/F3), else a description. The two targets are relative to the scratch
    path length (+300 and +600 bytes past the deep_scratch base) and capped below
    PATH_MAX, so they stay valid on a deep checkout (R5-F3)."""
    cap = path_max(tmp) - 1
    base_len = deep_scratch_base_len(tmp)
    if base_len + 2 > cap:  # deep_scratch cannot extend a path by one byte (R6-F2)
        return (f"the scratch path is {len(os.fsencode(str(tmp)))} bytes; deep_scratch needs "
                f"room below the {cap + 1}-byte PATH_MAX")
    for want in (min(base_len + 300, cap), min(base_len + 600, cap)):
        base = None
        try:
            base, cur = deep_scratch(tmp, want)
            got = len(os.fsencode(str(cur)))
            if got != want:
                return f"deep_scratch({want}) built a {got}-byte path, not the exact length"
        except OSError as exc:
            return f"deep_scratch({want}) raised {type(exc).__name__}: {exc}"
        finally:
            if base is not None:
                shutil.rmtree(base, ignore_errors=True)
    try:
        deep_scratch(tmp, 10)
    except OSError:
        pass
    else:
        return "deep_scratch with a target shorter than its base did not fail"
    left = sorted(p.name for p in tmp.glob("gitshim-deep.*"))
    if left:
        return f"a failed deep_scratch left {left!r} behind"
    real, boom = globals()["deep_scratch"], OSError(28, "No space left on device")

    def failing(_tmp, _target):
        raise boom
    globals()["deep_scratch"] = failing
    try:
        res = shim_boundary_robustness_violation(tmp)
    except Exception as exc:  # noqa: BLE001 - the cell must report, never raise
        return f"a deep_scratch build failure raised {type(exc).__name__}: {exc}"
    finally:
        globals()["deep_scratch"] = real
    if res is None or not res.startswith("could not build the near-PATH_MAX scratch"):
        return f"a deep_scratch build failure gave {res!r}, not a named violation"
    return None


FALLBACK_PLATFORMS = (("darwin", 1024), ("freebsd14", 1024), ("openbsd7", 1024),
                      ("netbsd10", 1024), ("linux", 4096))


def path_max_fallback_violation(tmp):
    """None when path_max falls back to the platform's PATH_MAX (1024 on darwin and the
    BSDs, 4096 elsewhere) when os.pathconf raises or answers nonsense, else a
    description (#6145 R5-F1). os.pathconf and sys.platform are patched in place and
    restored."""
    real_pathconf, real_platform = os.pathconf, sys.platform

    def raising(_path, _name):
        raise OSError(errno.EINVAL, "PC_PATH_MAX unavailable")
    # the host's own platform first (False sorts first), so the last patch applied is never the host's and
    # a leaked sys.platform patch is visible on every host (R6-F3)
    plans = sorted(FALLBACK_PLATFORMS, key=lambda entry: entry[0] != real_platform)
    try:
        for plat, want in plans:
            for label, patch in (("raises", raising), ("answers 0", lambda _p, _n: 0),
                                 ("answers None", lambda _p, _n: None)):
                os.pathconf, sys.platform = patch, plat
                got = path_max(tmp)
                if got != want:
                    return (f"path_max fell back to {got} on {plat} when os.pathconf {label}, "
                            f"not the platform limit {want}")
    finally:
        os.pathconf, sys.platform = real_pathconf, real_platform
    return None


PATH_MAX_LEAK_PREFIX = "path_max_fallback_violation leaked"
PATH_MAX_FALLBACK_PLANT = "planted fallback failure 6145"


def path_max_restore_violation(tmp, fallback=path_max_fallback_violation):
    """None when the fallback check (path_max_fallback_violation unless a caller passes
    another) hands os.pathconf and sys.platform back exactly as it found them AND
    passes, else a description (#6145 R6-F3). It is the only caller of
    path_max_fallback_violation and runs first in the cell list, so the snapshot is the
    true entry state and a leak names the real host platform (R7-F1). The patch list
    ends on a platform that is not the host's, so a dropped restore is visible on Linux
    too. The check is a parameter, not a patched global, so the diagnostic can hand in
    a leaking one without anything to put back (R8-F2)."""
    saved_pathconf, saved_platform = os.pathconf, sys.platform
    try:
        res = fallback(tmp)
    finally:
        leaked = []
        if os.pathconf is not saved_pathconf:
            leaked.append("os.pathconf")
        if sys.platform != saved_platform:
            leaked.append(f"sys.platform ({sys.platform!r}, not {saved_platform!r})")
        os.pathconf, sys.platform = saved_pathconf, saved_platform
    if leaked:
        return f"{PATH_MAX_LEAK_PREFIX} a patched {', '.join(leaked)}"
    return res


def path_max_restore_diagnostic_violation(tmp):
    """None when the path-max-restore cell, handed a fallback check that leaks its
    patches (what a dropped `finally` does), fails with a leak message naming the REAL
    host platform and puts os.pathconf and sys.platform back, and, handed a fallback
    check that fails without leaking, fails as `(path-max-fallback, #6145)`, else a
    description (#6145 R7-F1, R8-F1, R8-F2, R9-F3). Only that one cell runs (once per
    planted check), through the same run_cells loop as _self_test, with the planted
    check passed as its `fallback` argument: no global is patched, no other cell
    re-runs and no scratch dir is created, so the diagnostic adds no checkout depth
    (the 184-byte limit holds)."""
    host, real_pathconf = sys.platform, os.pathconf

    def leaking(_tmp):
        for plat, _want in sorted(FALLBACK_PLATFORMS, key=lambda entry: entry[0] != sys.platform):
            os.pathconf, sys.platform = (lambda _p, _n: 0), plat
        return None
    def planted(_tmp):
        return PATH_MAX_FALLBACK_PLANT
    err, fb_err = io.StringIO(), io.StringIO()
    try:
        with contextlib.redirect_stderr(err):
            rc = run_cells(SelfTest(), (("path-max-restore", path_max_restore_violation, (tmp, leaking)),))
        put_back = os.pathconf is real_pathconf and sys.platform == host
        with contextlib.redirect_stderr(fb_err):
            fb_rc = run_cells(SelfTest(), (("path-max-restore", path_max_restore_violation, (tmp, planted)),))
    finally:
        os.pathconf, sys.platform = real_pathconf, host
    out, fb_out = err.getvalue().strip(), fb_err.getvalue().strip()
    if not put_back:
        return ("the path-max-restore cell did not put os.pathconf and sys.platform back "
                "after a leaking fallback check")
    if rc != 2:
        return f"a leaking fallback check was not reported (rc {rc}): {out[-300:]!r}"
    if f"(path-max-restore, #6145): {PATH_MAX_LEAK_PREFIX}" not in out:
        return f"a leaking fallback check was reported as another failure: {out[-300:]!r}"
    if f"not {host!r}" not in out:
        return (f"the leak message does not name the real host platform {host!r}: "
                f"{out[-300:]!r}")
    if fb_rc != 2 or f"(path-max-fallback, #6145): {PATH_MAX_FALLBACK_PLANT}" not in fb_out:
        return (f"a failing (not leaking) fallback check was not reported as path-max-fallback "
                f"(rc {fb_rc}): {fb_out[-300:]!r}")
    return None


def guarded_violation():
    """None when guarded() turns an Exception into '<cell> raised <Type>: <msg>',
    returns None for a passing cell and lets KeyboardInterrupt propagate, else a
    description (#6145 R5-F2)."""
    def boom():
        raise RuntimeError("x")

    def fine():
        return None

    def interrupted():
        raise KeyboardInterrupt
    try:
        got = guarded(boom)
    except Exception as exc:  # noqa: BLE001 - an unguarded crash is the defect under test
        return f"guarded let a RuntimeError escape: {exc}"
    if got != "boom raised RuntimeError: x":
        return f"guarded gave {got!r} for a raising cell, not 'boom raised RuntimeError: x'"
    if guarded(fine) is not None:
        return "guarded changed the result of a passing cell"
    try:
        guarded(interrupted)
    except KeyboardInterrupt:
        return None
    return "guarded swallowed a KeyboardInterrupt"


def scratch_limit_message_violation(tmp):
    """None when the 'scratch path is too deep' violation names the actual scratch path
    length and the limit, else a description (#6145 R5-F3). The limit is derived here
    independently of the code under test: 255 - '#!' - ' -I' - '/gitshim-long.XXXXXXXX'
    - the pad's 1 byte and the 1-byte file name."""
    limit = 255 - len("#!") - len(" -I") - (1 + MKDTEMP_NAME_LEN) - 2
    base, deepest = deep_scratch(tmp, limit + 40)
    try:
        msg = shim_interpreter_violation(deepest)
    finally:
        shutil.rmtree(base, ignore_errors=True)
    if msg is None or not msg.startswith("the scratch path is too deep"):
        return f"a {limit + 40}-byte scratch gave {msg!r}, not a 'too deep' violation"
    for need in (f"{limit + 40} bytes", f"{limit} bytes"):
        if need not in msg:
            return f"the 'too deep' message {msg!r} does not state {need!r}"
    return None


def deep_scratch_relative_violation(tmp):
    """None when deep_scratch_violation stays valid on a deep scratch dir (its targets
    are relative to the scratch path length and capped below PATH_MAX), else a
    description (#6145 R5-F3)."""
    limit = path_max(tmp)
    base, deepest = deep_scratch(tmp, max(limit - 700, len(os.fsencode(str(tmp))) + 100))
    try:
        res = deep_scratch_violation(deepest)
    finally:
        shutil.rmtree(base, ignore_errors=True)
    return res


def deep_scratch_cap_violation(tmp):
    """None when deep_scratch_violation keeps its two targets inside
    [deep_scratch_base_len, PATH_MAX-1] on a scratch dir 400 bytes under PATH_MAX (where
    the +600 target hits the cap) and reports a named 'needs room' violation at 24 bytes
    under PATH_MAX (base 2 bytes under it) but not at 25 (R6-F1, R6-F2, R7-F2), else a
    description (#6145)."""
    limit = path_max(tmp)
    cap = limit - 1
    seen = []
    real = globals()["deep_scratch"]

    def spy(spy_tmp, target):
        seen.append(target)
        return real(spy_tmp, target)
    base, deepest = deep_scratch(tmp, limit - 400)
    globals()["deep_scratch"] = spy
    try:
        res = deep_scratch_violation(deepest)
    finally:
        globals()["deep_scratch"] = real
        shutil.rmtree(base, ignore_errors=True)
    if res is not None:
        return f"deep_scratch_violation failed on a scratch {limit - 400} bytes long: {res}"
    low = deep_scratch_base_len(deepest)
    targets = seen[:2]  # the two build targets come before the too-short probe
    if len(targets) != 2 or cap not in targets:
        return f"the deep_scratch targets {seen!r} never reached the cap {cap}"
    if any(t > cap or t < low for t in targets):
        return f"the deep_scratch targets {targets!r} leave [{low}, {cap}]"
    if targets != [min(low + 300, cap), min(low + 600, cap)]:
        return f"the deep_scratch targets {targets!r} are not base+300 and base+600 capped at {cap}"
    for room, want_room in ((limit - 24, True), (limit - 25, False)):
        base, deepest = deep_scratch(tmp, room)
        try:
            res = deep_scratch_violation(deepest)
        finally:
            shutil.rmtree(base, ignore_errors=True)
        if want_room:
            need = f"the scratch path is {room} bytes; deep_scratch needs room"
            if res is None or not res.startswith(need):
                return f"a {room}-byte scratch gave {res!r}, not a violation starting {need!r}"
        elif res is not None:
            return f"a {room}-byte scratch gave {res!r}, not None"
    return None


CHECKOUT_DEPTH_PREFIX = "cert-expiry-depth."


def checkout_depth_cells():
    """The cells checkout_depth_violation runs in its 226-byte scratch dir (#6145 R10-F1)."""
    return (shim_isolation_violation, shim_interpreter_violation,
            shim_boundary_robustness_violation, deep_scratch_violation,
            path_max_restore_diagnostic_violation, deep_scratch_cap_violation,
            scratch_limit_message_violation, deep_scratch_relative_violation,
            shim_unexecutable_violation)


# Cells whose scratch path or shim interpreter line grows with the scratch depth; each
# must run in checkout_depth_violation's 226-byte scratch dir (#6145 R10-F1).
CHECKOUT_DEPTH_REQUIRED = ("shim_unexecutable_violation",)


def checkout_depth_coverage_violation():
    """None when checkout_depth_cells() names every cell in CHECKOUT_DEPTH_REQUIRED, else
    a description (#6145 R10-F1): the shim-unexecutable cell's interpreter line is 251
    bytes at a 226-byte scratch dir, so a cell left out of checkout-depth lets a deeper
    one pass from a shallow checkout."""
    have = {cell.__name__ for cell in checkout_depth_cells()}
    missing = [name for name in CHECKOUT_DEPTH_REQUIRED if name not in have]
    if missing:
        return f"checkout-depth does not run {', '.join(missing)}"
    return None


def checkout_depth_violation(tmp):
    """None when every #6145 shim and scratch cell passes in a scratch dir exactly
    SCRATCH_PATH_LIMIT (226) bytes long, the scratch a 184-byte checkout gets, else a
    description (#6145 R8-F1, R9-F2). No cell may need more depth than shim-interpreter
    itself, so a cell that nests the self-test (or any of its cells) deeper than its
    own scratch dir fails here (checkout_depth_cells lists them; the checkout-depth-coverage
    cell pins shim_unexecutable_violation in it). path_max_restore_violation builds no
    path and is not in the list; the diagnostic still runs it, but only with planted
    fallbacks, so the real fallback check runs once per self-test (R9-F1); the gate-run
    fixtures build one `gitshim.*` level under the scratch dir and fit within it. The
    dir is a sibling of tmp (tmp itself is 226 bytes at a 184-byte checkout) and is
    removed afterwards."""
    parent = tmp.parent
    pad = SCRATCH_PATH_LIMIT - len(os.fsencode(str(parent))) - 1 - len(CHECKOUT_DEPTH_PREFIX) - 8
    if pad < 0:
        return (f"the scratch root {str(parent)!r} is too deep to build a "
                f"{SCRATCH_PATH_LIMIT}-byte scratch dir")
    deep = Path(tempfile.mkdtemp(prefix=CHECKOUT_DEPTH_PREFIX + "d" * pad, dir=str(parent)))
    try:
        got = len(os.fsencode(str(deep)))
        if got != SCRATCH_PATH_LIMIT:
            return f"the depth scratch dir is {got} bytes, not {SCRATCH_PATH_LIMIT}"
        for cell in checkout_depth_cells():
            res = guarded(cell, deep)
            if res is not None:
                return f"{cell.__name__} failed in a {got}-byte scratch dir: {res}"
    finally:
        shutil.rmtree(deep, ignore_errors=True)
    return None


def shim_isolation_violation(tmp, interpreter=None):
    """None when the git shim is isolated, else a description (#6145). Plants an
    empty `gitshim_canary_6145.py` beside the shim and runs the shim's own probe,
    which reports `sys.flags.isolated` and whether the canary imported (without
    -I the script directory is sys.path[0], so a planted module imports). The
    real import system decides, so a symlinked scratch path cannot fool it."""
    real = shutil.which("git")
    if real is None:
        raise GateError("git is not on PATH")
    shim_dir = Path(tempfile.mkdtemp(prefix="gitshim-iso.", dir=str(tmp)))
    try:
        shim = write_git_shim(shim_dir, real, interpreter=interpreter)
        (shim_dir / "gitshim_canary_6145.py").write_text("", encoding="utf-8")
        first = shim.read_text(encoding="utf-8").splitlines()[0]
        if not first.startswith("#!") or first.split()[1:] != ["-I"]:
            return f"shim interpreter line {first!r} is not '<python> -I'"
        try:
            res = subprocess.run([str(shim), "--shim-isolation-probe"], capture_output=True,
                                 text=True, cwd=str(shim_dir), check=False)
        except OSError as exc:
            return f"the shim could not be executed: {exc}"
        if res.returncode != 0 or res.stdout.split() != ["1", "False"]:
            return ("the shim is not isolated: probe printed "
                    f"{res.stdout.strip()!r} (want '1 False'), rc {res.returncode}: {res.stderr}")
        return None
    finally:
        shutil.rmtree(shim_dir, ignore_errors=True)


def run_gate_shimmed(tmp, repo, env, version="", fail=""):
    """run_gate with a PATH shim `git` that reports `version` for --version
    and exits 128 on any call whose argv contains `fail`, and otherwise
    delegates to the real git (R2-F2: pins the guarded branches)."""
    real = shutil.which("git")
    if real is None:
        raise GateError("git is not on PATH")
    shim_dir = Path(tempfile.mkdtemp(prefix="gitshim.", dir=str(tmp)))
    write_git_shim(shim_dir, real, version, fail)
    saved = os.environ.get("PATH")
    os.environ["PATH"] = f"{shim_dir}{os.pathsep}{saved or ''}"
    try:
        return run_gate(repo, dict(env, PATH=os.environ["PATH"]))
    finally:
        if saved is None:
            os.environ.pop("PATH", None)
        else:
            os.environ["PATH"] = saved
        shutil.rmtree(shim_dir, ignore_errors=True)


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


def guarded(cell, *args, **kwargs):
    """Run a self-test cell; a crash becomes a named violation string, not a traceback
    (#6145 security O1)."""
    try:
        return cell(*args, **kwargs)
    except Exception as exc:  # noqa: BLE001 - report any crash as a named failure
        return f"{cell.__name__} raised {type(exc).__name__}: {exc}"


def run_cells(t, cells):
    """Run (tag, cell, args) self-test cells in order (#6145 R8-F1). The first violation
    is reported through t.fail as `(<tag>, #6145): <violation>` and returns 2; None when
    every cell passes. A path-max-restore violation that is not a leak is tagged
    path-max-fallback, since the fallback check runs inside that cell."""
    for tag, cell, cell_args in cells:
        try:
            res = guarded(cell, *cell_args)
        except Exception as exc:  # noqa: BLE001 - guarded itself must never leak a crash
            res = f"{cell.__name__} escaped guarded: {type(exc).__name__}: {exc}"
        if res is not None:
            if tag == "path-max-restore" and not res.startswith(PATH_MAX_LEAK_PREFIX):
                tag = "path-max-fallback"  # the fallback check runs inside the restore cell
            t.fail(f"({tag}, #6145): {res}")
            print("check-cert-expiry self-test: FAIL", file=sys.stderr)
            return 2
    return None


def shim_unexecutable_violation(tmp):
    """None when a shim whose interpreter does not exist is reported as 'the shim could
    not be executed', else a description (#6145 R10-F1). The interpreter line is 251
    bytes at a 226-byte scratch dir, so checkout-depth runs this cell too."""
    unexec = guarded(shim_isolation_violation, tmp, interpreter=tmp / "no-such-python-6145")
    if unexec is None or not unexec.startswith("the shim could not be executed"):
        return (f"an unexecutable shim gave {unexec!r}, "
                "not a 'the shim could not be executed' violation")
    return None


def shim_isolation_result(tmp, check=shim_isolation_violation):
    """The shim-isolation verdict for _self_test: None when `check(tmp)` passes, else a
    description. A GateError is the description itself; any other crash becomes the
    `guarded` form, so a crash is a named failure and not a traceback (#6145 R10-F2)."""
    try:
        return check(tmp)
    except GateError as exc:
        return str(exc)
    except Exception as exc:  # noqa: BLE001 - report any crash as a named failure
        return f"shim_isolation_violation raised {type(exc).__name__}: {exc}"


def shim_isolation_crash_violation():
    """None when shim_isolation_result turns an OSError, a ValueError and a class defined
    here raised by the check into `shim_isolation_violation raised <Type>: ...`, else a
    description. The private class derives from Exception only, so no narrower tuple of
    builtin types catches it: the three plants pin the handler at Exception. Decoding the
    probe output of non-UTF-8 bytes raises UnicodeDecodeError, a ValueError (#6145 R10-F2,
    R11-F1, R12-F1)."""
    class _Planted6145(Exception):
        pass

    for exc_type in (OSError, ValueError, _Planted6145):
        def crashing(_tmp, exc_type=exc_type):
            raise exc_type("planted 6145")
        got = shim_isolation_result(None, crashing)
        want = f"shim_isolation_violation raised {exc_type.__name__}: planted 6145"
        if got != want:
            return f"{exc_type.__name__} raised in the isolation cell gave {got!r}, not {want!r}"
    return None


def _self_test(tmp):  # noqa: C901 - one linear plant-a-violation corpus
    repo = tmp / "repo"
    repo.mkdir()
    t = SelfTest()
    # #6145: prove the git PATH shim is isolated before any gate run uses it; an
    # unisolated shim aborts the self-test here.
    iso = shim_isolation_result(tmp)
    if iso is not None:
        t.fail(f"(shim-isolation, #6145): {iso}")
        print("check-cert-expiry self-test: FAIL", file=sys.stderr)
        return 2
    iface = guarded(shim_interpreter_violation, tmp)
    if iface is not None:
        t.fail(f"(shim-interpreter, #6145): {iface}")
        print("check-cert-expiry self-test: FAIL", file=sys.stderr)
        return 2
    robust = guarded(shim_boundary_robustness_violation, tmp)
    if robust is not None:
        t.fail(f"(shim-interpreter-robust, #6145): {robust}")
        print("check-cert-expiry self-test: FAIL", file=sys.stderr)
        return 2
    deepx = guarded(deep_scratch_violation, tmp)
    if deepx is not None:
        t.fail(f"(shim-deep-scratch, #6145): {deepx}")
        print("check-cert-expiry self-test: FAIL", file=sys.stderr)
        return 2
    rc = run_cells(t, (("path-max-restore", path_max_restore_violation, (tmp,)),
                       ("path-max-diagnostic", path_max_restore_diagnostic_violation, (tmp,)),
                       ("shim-deep-cap", deep_scratch_cap_violation, (tmp,)),
                       ("guarded", guarded_violation, ()),
                       ("shim-isolation-crash", shim_isolation_crash_violation, ()),
                       ("checkout-depth-coverage", checkout_depth_coverage_violation, ()),
                       ("shim-scratch-limit", scratch_limit_message_violation, (tmp,)),
                       ("shim-deep-relative", deep_scratch_relative_violation, (tmp,)),
                       ("checkout-depth", checkout_depth_violation, (tmp,))))
    if rc is not None:
        return rc
    rc = run_cells(t, (("shim-unexecutable", shim_unexecutable_violation, (tmp,)),))
    if rc is not None:
        return rc
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
    rc, out, err = run_gate_shimmed(tmp, repo, env7, version="git version 2.29.9")
    if rc != 1 or "git >= 2.30 is required" not in out + err:
        t.fail("(gitver): git 2.29.9 did not fail closed with the version guard:", out + err)
    rc, out, err = run_gate_shimmed(tmp, repo, env7, fail="--is-ancestor")
    if rc != 1 or "merge-base --is-ancestor exited 128" not in out + err:
        t.fail("(anc-error): an is-ancestor error did not fail closed:", out + err)
    rc, out, err = run_gate_shimmed(tmp, repo, env7)
    if rc != 0:
        t.fail("(shim-control): the pass-through git shim was REJECTED:", out + err)
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

    _trusted_cells(tmp, t, sentence)

    if t.failed:
        print("check-cert-expiry self-test: FAIL", file=sys.stderr)
        return 2
    print(SELF_TEST_OK)
    return 0


# ---------------------------------------------------------------------------
# #6140: --trusted mode cells (the pull_request_target companion job)
# ---------------------------------------------------------------------------

# Pinned literals (R5 precedent, #5164): dropping a trusted path, or drifting the
# trailer from scripts/claude-md-rule-compare.py, fails here instead of silently.
PINNED_TRUSTED_PATHS = ("scripts/check_cert_expiry.py", ".github/workflows/cert-expiry-trusted.yml",
                        "scripts/check-claude-md-size.py")
PINNED_TRUSTED_JOB = (".github/workflows/c8-precheck.yml", "cert-expiry-gate")
PINNED_TRAILER_LINE = 'TRAILER = re.compile(r"^Rule-Change-Approved-By: (\\S.*)$", re.MULTILINE)'

STUB_GATE = "import sys\nsys.exit(0)  # a gate copy that always passes\n"
C8_FIXTURE = (
    "name: c8\non: [pull_request]\njobs:\n"
    "  other-job:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo other\n"
    "  cert-expiry-gate:\n    name: Enterprise-federation cert-expiry gate (cert §7 / F7)\n"
    "    runs-on: ubuntu-latest\n    steps:\n      - run: python3 -I scripts/check_cert_expiry.py\n"
    "  # a comment at job indent belongs to the next job\n"
    "  later-job:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo later\n"
)
# Round 3: the trusted workflow in its real shape (every line of it that spells
# a fragment of the required check name), so the shadow scan is exercised on it.
TRUSTED_WF_FIXTURE = (
    "name: Enterprise-federation cert-expiry gate (trusted base copy)\n"
    "on:\n  pull_request_target:\n    branches: [main, develop, \"release/**\"]\n"
    "permissions:\n  contents: read\n"
    "concurrency:\n  group: cert-expiry-trusted-${{ github.event.pull_request.number }}\n"
    "  cancel-in-progress: true\n"
    "jobs:\n  cert-expiry-trusted:\n"
    "    name: Enterprise-federation cert-expiry gate, trusted base copy (cert §7 / F7)\n"
    "    runs-on: ubuntu-latest\n    timeout-minutes: 10\n    steps:\n"
    "      - name: Cert-expiry gate self-test (base code)\n"
    "        run: python3 -I scripts/check_cert_expiry.py --self-test\n"
)
SHADOW_JOB_FIXTURE = ("  shadow:\n    name: Enterprise-federation cert-expiry gate (cert §7 / F7)\n"
                      "    runs-on: ubuntu-latest\n    steps:\n      - run: echo always-green\n")


def trusted_cli(repo, *args):
    """Run main() in --trusted mode against `repo`; (rc, combined output). An
    argparse refusal (an unknown flag on a gate without the mode) is rc 2."""
    out, err = io.StringIO(), io.StringIO()
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = main(["--trusted", "--repo", str(repo), *args])
    except SystemExit as exc:
        rc = exc.code if isinstance(exc.code, int) else 2
    return rc, out.getvalue() + err.getvalue()


def _trusted_cells(tmp, t, sentence):  # noqa: C901 - one linear corpus
    """Build a fixture, mirror it to a BARE repository (no working tree at all,
    so nothing can be checked out or executed from the head) and judge each
    pull request shape the way cert-expiry-trusted.yml does."""
    trusted = globals().get("TRUSTED_PATHS")
    if trusted != PINNED_TRUSTED_PATHS:
        t.fail(f"(tr-pin): TRUSTED_PATHS {trusted!r} differs from the pinned set {PINNED_TRUSTED_PATHS!r}")
    if globals().get("TRUSTED_JOB") != PINNED_TRUSTED_JOB:
        t.fail(f"(tr-pin): TRUSTED_JOB {globals().get('TRUSTED_JOB')!r} differs from {PINNED_TRUSTED_JOB!r}")
    trailer = globals().get("TRAILER")
    compare_src = REPO_ROOT / "scripts" / "claude-md-rule-compare.py"
    try:
        compare_text = compare_src.read_text(encoding="utf-8")
    except OSError as exc:
        compare_text = ""
        t.fail(f"(tr-trailer): cannot read {compare_src}: {exc}")
    if PINNED_TRAILER_LINE not in compare_text:
        t.fail("(tr-trailer): scripts/claude-md-rule-compare.py no longer defines the pinned approval trailer")
    if trailer is None or trailer.pattern != r"^Rule-Change-Approved-By: (\S.*)$":
        t.fail("(tr-trailer): the cert gate's TRAILER is not the claude-md-rule-compare approval trailer")

    repo = tmp / "trusted-repo"
    repo.mkdir()
    fx = Fixture(repo)
    fx.g("init", "-q", "-b", "main")
    fx.g("config", "user.name", "Cert Expiry Selftest")
    fx.g("config", "user.email", "selftest@invalid.example")
    fx.g("config", "commit.gpgsign", "false")
    mod_rs = "src/federation/mod.rs"
    gate_rel, wf_rel, pin_rel = PINNED_TRUSTED_PATHS
    c8_rel = PINNED_TRUSTED_JOB[0]
    fx.write(mod_rs, "fn federation_mod() {}\n")
    fx.write("src/unrelated.rs", "fn other() {}\n")
    fx.write(gate_rel, "# the base copy of the gate (fixture)\n")
    fx.write(wf_rel, TRUSTED_WF_FIXTURE)
    fx.write(pin_rel, "# the canonical-form pin (fixture)\n")
    fx.write(c8_rel, C8_FIXTURE)
    genesis = fx.commit(["src", "scripts", ".github"], "genesis")
    fx.banner("LIVE", genesis)
    base = fx.commit([CERT_DOC], "base: certification LIVE bound to genesis")
    fx.g("update-ref", "refs/remotes/origin/main", base)
    approve = "\n\nRule-Change-Approved-By: Selftest Approver"

    def pr(name, edits, trailer_msg=""):
        """A PR branch off `base` with `edits` {rel: text | callable}, merged
        into main with --no-ff; returns (head, merge). main is reset to base."""
        fx.g("checkout", "-q", "-b", name, base)
        for rel, text in edits.items():
            if callable(text):
                text(rel)
            else:
                fx.write(rel, text)
        fx.g("add", "-A")
        fx.g("commit", "-q", "-m", f"{name}: PR change{trailer_msg}")
        head = fx.g("rev-parse", "HEAD")
        fx.g("checkout", "-q", "main")
        merge = fx.merge(name, f"Merge {name} into main")
        fx.reset(base)
        return head, merge

    def symlink_doc(rel):
        (repo / rel).unlink()
        (repo / rel).symlink_to("../../src/unrelated.rs")

    wire = "fn federation_mod() {}\n// PR wire change\n"
    shapes = {
        "clean": pr("clean", {"src/unrelated.rs": "fn other() {}\n// unrelated\n"}),
        "stub": pr("stub", {mod_rs: wire, gate_rel: STUB_GATE}),
        "stubok": pr("stubok", {mod_rs: wire, gate_rel: STUB_GATE}, approve),
        "wire": pr("wire", {mod_rs: wire}),
        "wf": pr("wf", {wf_rel: "name: weakened (fixture)\n"}),
        "wfok": pr("wfok", {wf_rel: "name: weakened (fixture)\n"}, approve),
        "pin": pr("pin", {pin_rel: "# weakened pin\n"}),
        "gate": pr("gate", {gate_rel: STUB_GATE}),
        "job": pr("job", {c8_rel: C8_FIXTURE.replace("check_cert_expiry.py\n", "check_cert_expiry.py --self-test\n")}),
        "jobgone": pr("jobgone", {c8_rel: C8_FIXTURE.replace("  cert-expiry-gate:\n", "  renamed-gate:\n")}),
        "otherjob": pr("otherjob", {c8_rel: C8_FIXTURE.replace("echo other", "echo other2").replace(
            "echo later", "echo later2")}),
        "symlink": pr("symlink", {mod_rs: wire, CERT_DOC: symlink_doc}),
    }
    # Round 2 (#6140 security review F1): each c8-precheck.yml header key is guarded.
    headers = {
        "env": C8_FIXTURE.replace("jobs:\n", "env:\n  X: y\njobs:\n", 1),
        "on": C8_FIXTURE.replace("on: [pull_request]", "on: [pull_request, push]", 1),
        "permissions": C8_FIXTURE.replace("jobs:\n", "permissions:\n  contents: write\njobs:\n", 1),
        "defaults": C8_FIXTURE.replace("jobs:\n", "defaults:\n  run:\n    shell: bash\njobs:\n", 1),
    }
    for key, text in headers.items():
        shapes["hdr-" + key] = pr("hdr-" + key, {c8_rel: text})
    shapes["hdr-ok"] = pr("hdr-ok", {c8_rel: headers["env"]}, approve)
    # Round 2 (F3): a second producer of the required check name, anywhere in
    # .github/workflows at the merge commit, fails closed; a trailer does not waive it.
    shadow_job = ("  shadow:\n    name: Enterprise-federation cert-expiry gate (cert §7 / F7)\n"
                  "    runs-on: ubuntu-latest\n    steps:\n      - run: echo always-green\n")
    shadows = {
        "c8": {c8_rel: C8_FIXTURE + shadow_job},
        "new": {".github/workflows/shadow.yml": "name: s\non: [pull_request]\njobs:\n" + shadow_job},
        "copy": {".github/workflows/copy.yml": C8_FIXTURE},
        "escaped": {".github/workflows/esc.yaml": "name: e\non: [pull_request]\njobs:\n  esc:\n"
                    '    name: "Enterprise-federation cert\\x2Dexpiry gate (cert \\u00a7 / F7)"\n'
                    "    runs-on: ubuntu-latest\n    steps:\n      - run: echo always-green\n"},
        "folded": {".github/workflows/fold.yml": "name: f\non: [pull_request]\njobs:\n  fold:\n"
                   "    name: Enterprise-federation cert-expiry\n      gate (cert §7 / F7)\n"
                   "    runs-on: ubuntu-latest\n    steps:\n      - run: echo always-green\n"},
    }
    for key, edits in shadows.items():
        shapes["shadow-" + key] = pr("shadow-" + key, edits)
    shapes["shadow-ok"] = pr("shadow-ok", shadows["new"], approve)
    shapes["newwf"] = pr("newwf", {".github/workflows/lint.yml": "name: lint\non: [pull_request]\njobs:\n"
                                   "  lint:\n    name: Lint\n    runs-on: ubuntu-latest\n"
                                   "    steps:\n      - run: echo lint\n"})
    # #6175: names the change controls, carrying a newline / CR and a forged workflow command.
    forged = "::error title=forged::"
    shapes["log-watched"] = pr("log-watched", {f"src/federation/x\n{forged}y.rs": "fn x() {}\n"})
    shapes["log-shadow"] = pr("log-shadow", {f".github/workflows/x\n{forged}.yml": f"name: {CERT_CONTEXT_FIXTURE}\r# cr\u00a0\n"})
    shapes["log-who"] = pr("log-who", {wf_rel: "name: weakened (fixture)\n"},
                           f"\n\nRule-Change-Approved-By: Evil\r{forged}x")
    _round3_shapes(repo, shapes, pr, approve, wf_rel, c8_rel)
    _round4_shapes(shapes, pr, approve, wf_rel, c8_rel)
    _round5_shapes(shapes, pr, approve, wf_rel, c8_rel)
    # Merge-structure shapes off one PR head (#6138 cells, here in --trusted mode).
    fx.g("checkout", "-q", "-b", "h8", base)
    fx.write("src/unrelated.rs", "// h8 PR work\n", append=True)
    head8 = fx.commit(["src/unrelated.rs"], "h8: PR work")
    fx.g("checkout", "-q", "-b", "o8", base)
    fx.write("src/other8.rs", "fn other8() {}\n")
    fx.commit(["src/other8.rs"], "o8: an unrelated branch")
    fx.g("checkout", "-q", "main")
    good8 = fx.merge("h8", "Merge h8 into main")
    fx.reset(base)
    unrel8 = fx.merge("o8", "Merge o8 into main (not the PR head)")
    fx.reset(base)
    fx.g("merge", "-q", "--no-ff", "-m", "octopus: h8 and o8", "h8", "o8")
    octo8 = fx.g("rev-parse", "HEAD")
    fx.reset(base)
    # The base moves on first, so merging main INTO the head is a real
    # two-parent merge with the head as its first parent (reversed).
    fx.write("src/main8.rs", "fn main8() {}\n")
    moved8 = fx.commit(["src/main8.rs"], "base moves on with an unrelated commit")
    fx.g("checkout", "-q", "h8")
    rev8 = fx.merge("main", "Merge main into h8 (reversed parents)")
    fx.g("checkout", "-q", "-b", "side8", genesis)
    fx.write("src/side8.rs", "fn side8() {}\n")
    side8 = fx.commit(["src/side8.rs"], "a side branch the merge was not built from")
    fx.g("checkout", "-q", "main")
    fx.g("update-ref", "refs/remotes/pull/merge", shapes["clean"][1])

    # The judged repository is a BARE mirror: there is no working tree, so the
    # mode can only read git objects (the head is data, never checked out).
    mirror = tmp / "trusted-mirror.git"
    fx.g("clone", "-q", "--mirror", str(repo), str(mirror))
    mg = Fixture(mirror)
    mg.g("update-ref", "refs/remotes/origin/main", base)

    def judge(label, why, head, merge, needles=(), absent=(), ok=False, extra=()):
        rc, out = trusted_cli(mirror, "--base-ref=main", f"--base-sha={base}",
                              f"--head-sha={head}", f"--merge-ref={merge}", *extra)
        if ok and rc != 0:
            t.fail(f"({label}): {why} was REJECTED (rc {rc}):", out)
        elif not ok and rc != 1:
            t.fail(f"({label}): {why} did not fail closed with rc 1 (rc {rc}):", out)
        for needle in needles:
            if needle not in out:
                t.fail(f"({label}): {why}: output does not say {needle!r}:", out)
        for needle in absent:
            if needle in out:
                t.fail(f"({label}): {why}: output must not say {needle!r}:", out)
        return out

    guard = "GUARD CHANGED: "
    judge("tr0", "control: an unrelated PR change", *shapes["clean"], ok=True,
          needles=("federation-wire surface unchanged",), absent=(guard,))
    judge("tr0-ref", "control: the merge commit named by refs/remotes/pull/merge", shapes["clean"][0],
          "refs/remotes/pull/merge", ok=True)
    # (tr-a) the head replaces the gate with an exit-0 stub AND changes the wire:
    # the base copy still reds with the section 7 sentence, and names the guard edit.
    judge("tr-a", "a head that stubs the gate to exit 0 and changes the federation wire", *shapes["stub"],
          needles=(sentence, mod_rs, guard + gate_rel))
    stub_file = tmp / "head-gate-copy.py"
    stub_file.write_bytes(run_git(mirror, "show", f"{shapes['stub'][0]}:{gate_rel}").stdout)
    stub_rc = subprocess.run([sys.executable, "-I", str(stub_file)], capture_output=True, check=False,
                             timeout=60).returncode
    if stub_rc != 0:
        t.fail(f"(tr-a-control): the head's stub gate copy exited {stub_rc}, not 0; the cell proves nothing")
    # A trailer never waives the section 7 verdict.
    judge("tr-a2", "the same stub + wire change WITH the approval trailer", *shapes["stubok"],
          needles=(sentence, guard + gate_rel, "Selftest Approver"))
    # Environment overrides are not a range source in --trusted mode.
    saved = {k: os.environ.get(k) for k in ("CERT_EXPIRY_BASE", "CERT_EXPIRY_HEAD", "GITHUB_EVENT_NAME")}
    os.environ.update(CERT_EXPIRY_BASE=base, CERT_EXPIRY_HEAD=base, GITHUB_EVENT_NAME="workflow_dispatch")
    try:
        judge("tr-a3", "stub + wire change with CERT_EXPIRY_* / event overrides in the environment",
              *shapes["stub"], needles=(sentence,))
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    judge("tr-wire", "a PR wire change without a banner flip (pr6 shape)", *shapes["wire"],
          needles=(sentence, mod_rs), absent=(guard,))
    # (tr-b) a trusted path edited without / with the trailer.
    judge("tr-b", "the trusted workflow edited without the trailer", *shapes["wf"],
          needles=(guard + wf_rel, "Rule-Change-Approved-By"))
    judge("tr-b-ok", "the trusted workflow edited WITH the trailer", *shapes["wfok"], ok=True,
          needles=(guard + wf_rel, "approval trailer(s)", "Selftest Approver"))
    for label, rel in (("pin", pin_rel), ("gate", gate_rel)):
        judge(f"tr-b-{label}", f"{rel} edited without the trailer", *shapes[label], needles=(guard + rel,))
    job = guard + f"{c8_rel} ({PINNED_TRUSTED_JOB[1]} job)"
    judge("tr-b-job", "the cert-expiry-gate job block edited without the trailer", *shapes["job"], needles=(job,))
    judge("tr-b-jobgone", "the cert-expiry-gate job renamed away", *shapes["jobgone"], needles=(job,))
    judge("tr-b-other", "other jobs of c8-precheck.yml edited (not a guard change)", *shapes["otherjob"],
          ok=True, absent=(guard,))
    # (tr-d) a symlinked cert doc is refused, not followed or read as text.
    judge("tr-d", "the cert doc replaced by a symlink alongside a wire change", *shapes["symlink"],
          needles=("symlink",))
    # (tr-c) merge-parent structure, fail-closed with its reason.
    judge("tr-c-ok", "control: a two-parent merge of the base and the PR head", head8, good8, ok=True)
    judge("tr-c-second", "second parent is not the PR head", head8, unrel8, needles=("is not PR_HEAD_SHA",))
    judge("tr-c-octopus", "an octopus merge", head8, octo8, needles=("does not have exactly two parents",))
    judge("tr-c-reversed", "reversed parents", head8, rev8, needles=("reversed parents",))
    judge("tr-c-notmerge", "a merge ref that is not a merge commit", head8, base,
          needles=("does not have exactly two parents",))
    mg.g("update-ref", "refs/remotes/origin/main", moved8)
    judge("tr-c-moved", "base moved by an unrelated commit after the merge was built", head8, good8, ok=True,
          needles=(f"unchanged in {base}..{good8}",))
    mg.g("update-ref", "refs/remotes/origin/main", side8)
    judge("tr-c-offbase", "first parent not on the live base", head8, good8, needles=("is not on the live base",))
    mg.g("update-ref", "refs/remotes/origin/main", base)
    # (tr-e) argument refusals, before any git call reads a head-controlled value.
    hex_msg = "is not exactly 40 or 64 hex characters"
    judge("tr-e-head", "an abbreviated head sha", head8[:12], good8, needles=(hex_msg,))
    judge("tr-e-optref", "an option-shaped merge ref", head8, "--upload-pack=x", needles=("--merge-ref",))
    judge("tr-e-missing", "a merge ref that does not resolve", head8, "refs/remotes/pull/no-such",
          needles=("does not resolve",))
    rc, out = trusted_cli(mirror, "--base-ref=--upload-pack=x", f"--base-sha={base}",
                          f"--head-sha={head8}", f"--merge-ref={good8}")
    if rc != 1 or "is not a plain branch name" not in out:
        t.fail(f"(tr-e-baseref): an option-shaped base ref did not fail closed (rc {rc}):", out)
    rc, out = trusted_cli(mirror, "--base-ref", "main", "--merge-ref", good8)
    if rc == 0 or "--head-sha" not in out:
        t.fail(f"(tr-e-args): --trusted without --head-sha did not refuse (rc {rc}):", out)
    _trusted_round2_cells(tmp, t, judge, shapes, mirror, job)
    _trusted_log_cells(t, judge, shapes)
    _trusted_merge_ref_cells(t, fx, mirror, head8, good8, unrel8)
    _trusted_round3_cells(tmp, t, judge, shapes)
    _trusted_round4_cells(judge, shapes)
    _trusted_round5_cells(judge, shapes)
    _trusted_round3_fetch_cells(tmp, t, fx, mirror, head8, good8)
    _shim_trace_cells(t)
    _ws_unit_cells(t)
    _ws_format_cells(t)
    _ws_wording_cells(t)


CERT_CONTEXT_FIXTURE = "Enterprise-federation cert-expiry gate (cert §7 / F7)"
# Workflow commands this gate emits on purpose (annotation()); every other line
# must not read as a command after the runner's leading-whitespace trim.
OWN_COMMANDS = ("::warning title=GUARD CHANGED::", "::error title=cert-expiry trusted::")


def _trusted_log_cells(t, judge, shapes):
    """#6175: a name the change controls (a watched path, a workflow file name,
    an approval trailer) is printed with its control characters escaped, so it
    can never start a new step-log line that the runner reads as a workflow
    command (`::error`, `::add-mask`, ...)."""
    cells = (
        ("tr-log-watched", "a watched path carrying a newline and a forged ::error", "log-watched", False,
         "src/federation/x\\x0a::error title=forged::y.rs"),
        ("tr-log-shadow", "a workflow file name carrying a newline and a forged ::error", "log-shadow", False,
         ".github/workflows/x\\x0a::error title=forged::.yml"),
        ("tr-log-who", "an approval trailer carrying a CR and a forged ::error", "log-who", True,
         "Evil\\x0d::error title=forged::x"),
    )
    for label, why, key, ok, shown in cells:
        out = judge(label, why, *shapes[key], ok=ok, needles=(shown,))
        if "\r" in out:
            t.fail(f"({label}): {why}: a raw carriage return reached the log:", out)
        for line in out.splitlines():
            if line.lstrip().startswith("::") and not line.lstrip().startswith(OWN_COMMANDS):
                t.fail(f"({label}): {why}: the log line {line!r} reads as a workflow command", out)


# #6176: the merge ref is re-fetched a fixed number of times with fixed sleeps.
PINNED_MERGE_REF_SLEEPS = (5, 10, 20, 30)


def _trusted_merge_ref_cells(t, fx, mirror, head8, good8, unrel8):
    """#6176: with --pr-number the gate fetches refs/pull/<N>/merge itself and
    re-fetches a stale or missing merge ref with bounded backoff before it
    fails closed with an ::error annotation. Sleeps are recorded, not slept."""
    if globals().get("MERGE_REF_SLEEPS") != PINNED_MERGE_REF_SLEEPS:
        t.fail(f"(tr-m-pin): MERGE_REF_SLEEPS {globals().get('MERGE_REF_SLEEPS')!r} differs from "
               f"{PINNED_MERGE_REF_SLEEPS!r}")
    slept, on_sleep = [], []

    def fake_sleep(seconds):
        slept.append(seconds)
        if on_sleep:
            on_sleep.pop(0)()

    def set_ref(sha):
        if sha:
            fx.g("update-ref", "refs/pull/7/merge", sha)
        elif run_git(fx.repo, "rev-parse", "--verify", "--quiet", "refs/pull/7/merge").returncode == 0:
            fx.g("update-ref", "-d", "refs/pull/7/merge")

    def cell(label, why, sha, ok, needles=(), sleeps=(), args=("--pr-number=7", "--merge-ref=refs/remotes/pull/m7")):
        set_ref(sha)
        del slept[:]
        rc, out = trusted_cli(mirror, "--base-ref=main", f"--head-sha={head8}", *args)
        if ok and rc != 0:
            t.fail(f"({label}): {why} was REJECTED (rc {rc}):", out)
        elif not ok and rc != 1:
            t.fail(f"({label}): {why} did not fail closed with rc 1 (rc {rc}):", out)
        for needle in needles:
            if needle not in out:
                t.fail(f"({label}): {why}: output does not say {needle!r}:", out)
        if list(slept) != list(sleeps):
            t.fail(f"({label}): {why}: slept {slept!r}, expected the fixed backoff {list(sleeps)!r}", out)

    saved = globals().get("_sleep")
    globals()["_sleep"] = fake_sleep
    try:
        # #6163 precedent: no workflow step fetches the head; --pr-number makes this base copy fetch it.
        fx.g("update-ref", "refs/pull/7/head", head8)
        if run_git(mirror, "rev-parse", "--verify", "--quiet", "refs/remotes/pull/head").returncode == 0:
            Fixture(mirror).g("update-ref", "-d", "refs/remotes/pull/head")
        cell("tr-m-current", "a current merge ref on the first fetch", good8, True)
        fetched = run_git(mirror, "rev-parse", "--verify", "--quiet", "refs/remotes/pull/head^{commit}")
        if fetched.stdout.decode().strip() != head8:
            t.fail("(tr-m-head): --pr-number did not fetch refs/pull/7/head into refs/remotes/pull/head "
                   f"(got {fetched.stdout.decode().strip()!r}, rc {fetched.returncode})")
        on_sleep.append(lambda: set_ref(good8))
        cell("tr-m-late", "a merge ref that becomes current on the second fetch", unrel8, True, sleeps=(5,))
        del on_sleep[:]
        attempts = f"{len(PINNED_MERGE_REF_SLEEPS) + 1} fetch attempts"
        cell("tr-m-stale", "a merge ref that never becomes current", unrel8, False,
             needles=("::error title=cert-expiry trusted::", "stale", attempts), sleeps=PINNED_MERGE_REF_SLEEPS)
        cell("tr-m-missing", "no merge ref at all (a conflicted pull request)", "", False,
             needles=("::error title=cert-expiry trusted::", "conflict", attempts), sleeps=PINNED_MERGE_REF_SLEEPS)
        # Hostile --pr-number values (#6163 precedent) are refused before any git fetch runs.
        real_run_git, fetches = globals()["run_git"], []

        def recording_run_git(repo, *args, **kw):
            if "fetch" in args:
                fetches.append(args)
            return real_run_git(repo, *args, **kw)

        globals()["run_git"] = recording_run_git
        try:
            for bad in ("0", "07", "-1", "--upload-pack=touch pwned", "../7", "7/../8", "7\n", "\u0667",
                        "1" * 11, "7x", "", " 7"):
                del fetches[:]
                cell(f"tr-m-num-{bad[:6]!r}", f"--pr-number {bad!r}", good8, False, needles=("--pr-number",),
                     args=(f"--pr-number={bad}", "--merge-ref=refs/remotes/pull/m7"))
                if fetches:
                    t.fail(f"(tr-m-num-{bad[:6]!r}): --pr-number {bad!r} reached git: {fetches!r}")
        finally:
            globals()["run_git"] = real_run_git
        cell("tr-m-sha", "--pr-number with a sha --merge-ref", good8, False, needles=("--merge-ref",),
             args=("--pr-number=7", f"--merge-ref={good8}"))
    finally:
        if saved is None:
            globals().pop("_sleep", None)
        else:
            globals()["_sleep"] = saved


def _trusted_round2_cells(tmp, t, judge, shapes, mirror, job):
    """#6140 round 2 (security review F1-F4): header keys, git read errors,
    check-name shadowing, the blob cap and the approval annotation."""
    gate_rel = PINNED_TRUSTED_PATHS[0]
    guard = "GUARD CHANGED: "
    # (F1) every guarded c8-precheck.yml header key: RED without the trailer, GREEN with it.
    for key in ("env", "on", "permissions", "defaults"):
        judge(f"tr-h-{key}", f"a c8-precheck.yml `{key}:` header edit without the trailer", *shapes["hdr-" + key],
              needles=(job, "Rule-Change-Approved-By"))
    judge("tr-h-ok", "a c8-precheck.yml header edit WITH the trailer", *shapes["hdr-ok"], ok=True,
          needles=(job, "Selftest Approver"))
    # (F4) a trailer-approved guard change is surfaced as a workflow annotation.
    judge("tr-h-warn", "an approved guard change", *shapes["hdr-ok"], ok=True,
          needles=("::warning title=GUARD CHANGED::", "Selftest Approver"))
    # (F2) a git read error (missing object) is fail-closed, never read as "absent".
    missing = "0" * 40
    for label, call in (("tr-g-entry", lambda: tree_entry(mirror, missing, CERT_DOC)),
                        ("tr-g-banner", lambda: cert_banner(mirror, missing)),
                        ("tr-g-guard", lambda: guarded_state(mirror, missing, gate_rel))):
        try:
            got = call()
        except GateError as exc:
            if "ls-tree" not in str(exc):
                t.fail(f"({label}): a missing tree failed for the wrong reason: {exc}")
        else:
            t.fail(f"({label}): a git ls-tree error on a missing object read as {got!r} (fail-open)")
    rc, out = trusted_cli_shimmed(tmp, mirror, "ls-tree", shapes["clean"])
    if rc != 1 or "ls-tree" not in out:
        t.fail(f"(tr-g-e2e): --trusted with every git ls-tree failing did not fail closed (rc {rc}):", out)
    # (F4) the 2 MiB blob cap: an oversized cert doc is refused, not read.
    saved_cap = globals()["MAX_BLOB_BYTES"]
    globals()["MAX_BLOB_BYTES"] = 10
    try:
        judge("tr-cap", "a cert doc above the blob cap", *shapes["clean"], needles=("exceeds 10 bytes",))
    finally:
        globals()["MAX_BLOB_BYTES"] = saved_cap
    # (F3) a second producer of the required check name fails closed, trailer or not.
    shadow = "GUARD SHADOW: "
    for key, where in (("c8", ".github/workflows/c8-precheck.yml"), ("new", ".github/workflows/shadow.yml"),
                       ("copy", ".github/workflows/copy.yml"), ("escaped", ".github/workflows/esc.yaml"),
                       ("folded", ".github/workflows/fold.yml")):
        judge(f"tr-s-{key}", f"a shadow job named like the required context ({key})", *shapes["shadow-" + key],
              needles=(shadow + where,))
    judge("tr-s-ok", "a shadow job WITH the approval trailer (not waivable)", *shapes["shadow-ok"],
          needles=(shadow + ".github/workflows/shadow.yml",))
    judge("tr-s-control", "a new unrelated workflow file", *shapes["newwf"], ok=True, absent=(shadow, guard))
    judge("tr-s-other", "other c8 jobs edited", *shapes["otherjob"], ok=True, absent=(shadow, guard))


def _round3_shapes(repo, shapes, pr, approve, wf_rel, c8_rel):
    """#6140 round 3 shapes: shadow producers inside the trailer-waivable
    regions (each WITH the trailer), the R2-3 test-gap shapes and controls."""
    ctx = "Enterprise-federation cert-expiry gate (cert §7 / F7)"
    named = f"    name: {ctx}\n"
    alias_job = "  shadow:\n    name: *ctx\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo always-green\n"
    gate_env = named + f"    env:\n      CTX: &ctx {ctx}\n"

    def symlink_wf(rel):
        (repo / rel).symlink_to("c8-precheck.yml")

    def wf_blob(rel):
        shutil.rmtree(repo / rel)
        (repo / rel).write_text("not a directory\n", encoding="utf-8")

    amp = C8_FIXTURE.replace(
        "  later-job:\n    runs-on: ubuntu-latest\n",
        "  later-job:\n    if: github.event_name == 'pull_request' && true\n    runs-on: ubuntu-latest\n"
        "    env:\n      GLOB: \"release/**\"\n", 1).replace(
        "      - run: echo later\n",
        "      - run: echo later\n      - run: |\n          case \"$x\" in\n"
        "            *) [ -n \"$x\" ] && echo *.txt ;;\n          esac\n", 1)
    split = ("name: split\non: [pull_request]\njobs:\n  split:\n"
             "    name: \"Enterprise-federation cert-ex\\\n      piry gate (cert §\\\n      7 / F7)\"\n"
             "    runs-on: ubuntu-latest\n    steps:\n      - run: echo always-green\n")
    r3 = {
        "trusted": ({wf_rel: TRUSTED_WF_FIXTURE.replace("on:\n", "on:\n  pull_request:\n", 1)
                     + SHADOW_JOB_FIXTURE}, approve),
        "quoted": ({c8_rel: C8_FIXTURE + SHADOW_JOB_FIXTURE.replace("  shadow:", '  "shadow":', 1)}, approve),
        "flow": ({c8_rel: C8_FIXTURE + f'  shadow: {{name: "{ctx}", runs-on: ubuntu-latest, '
                  "steps: [{run: echo always-green}]}\n"}, approve),
        "anchor": ({c8_rel: C8_FIXTURE.replace(named, named.replace("name: ", "name: &ctx "), 1) + alias_job},
                   approve),
        "anchor-hdr": ({c8_rel: C8_FIXTURE.replace("jobs:\n", f"env:\n  CTX: &ctx {ctx}\njobs:\n", 1) + alias_job},
                       approve),
        "anchor-env": ({c8_rel: C8_FIXTURE.replace(named, gate_env, 1) + alias_job}, approve),
        "trusted-name": ({wf_rel: TRUSTED_WF_FIXTURE.replace("gate, trusted base copy (cert", "gate (cert", 1)},
                         approve),
        "trusted-hdr": ({wf_rel: TRUSTED_WF_FIXTURE.replace("jobs:\n", f"env:\n  CTX: {ctx}\njobs:\n", 1)}, approve),
        "c8-hdr": ({c8_rel: C8_FIXTURE.replace("jobs:\n", f"env:\n  CTX: {ctx}\njobs:\n", 1)}, approve),
        "flow-anchor": ({c8_rel: C8_FIXTURE.replace(named, named + f"    env: {{CTX: &ctx {ctx}}}\n", 1)}, approve),
        "flow-span": ({c8_rel: C8_FIXTURE.replace("jobs:\n", "env: {A: x,\n  B: y}\njobs:\n", 1)}, approve),
        "trusted-ok": ({wf_rel: TRUSTED_WF_FIXTURE.replace("timeout-minutes: 10", "timeout-minutes: 9", 1)}, approve),
        "amp": ({c8_rel: amp}, ""),
        "split": ({".github/workflows/split.yml": split}, ""),
        "log-sep": ({"src/federation/a b.rs": "fn a() {}\n", "src/federation/c\x85d.rs": "fn c() {}\n"}, ""),
        "pct": ({wf_rel: TRUSTED_WF_FIXTURE.replace("timeout-minutes: 10", "timeout-minutes: 8", 1)},
                "\n\nRule-Change-Approved-By: Pct%0A::error title=forged::x"),
        "symwf": ({".github/workflows/s.yml": symlink_wf}, approve),
        "wfblob": ({".github/workflows": wf_blob}, approve),
        "bigname": ({".github/workflows/x\n::error title=forged::big.yml": "# " + "x" * 8192 + "\n"}, ""),
    }
    for key, (edits, trailer_msg) in r3.items():
        shapes["r3-" + key] = pr("r3-" + key, edits, trailer_msg)


def _no_forged_lines(t, label, why, out):
    """No step-log line of OUT reads as a workflow command this gate did not emit."""
    for line in out.splitlines():
        if line.lstrip().startswith("::") and not line.lstrip().startswith(OWN_COMMANDS):
            t.fail(f"({label}): {why}: the log line {line!r} reads as a workflow command", out)


def _trusted_round3_cells(tmp, t, judge, shapes):
    """#6140 round 3 (code review F1/F2, security review R2-1..R2-3): no
    region a trailer can waive hides a second producer of the required check
    name, and the R2-3 properties each have a cell of their own."""
    shadow, guard = "GUARD SHADOW: ", "GUARD CHANGED: "
    c8, wf = PINNED_TRUSTED_JOB[0], PINNED_TRUSTED_PATHS[1]
    for key, where, says in (("trusted", wf, "job 'shadow'"), ("quoted", c8, '"shadow"'),
                             ("flow", c8, "shadow: {name"), ("anchor", c8, "anchor"),
                             ("anchor-hdr", c8, "anchor"), ("anchor-env", c8, "anchor"),
                             ("trusted-name", wf, "pinned"), ("trusted-hdr", wf, "workflow header"),
                             ("c8-hdr", c8, "workflow header"), ("flow-anchor", c8, "anchor in a flow collection"),
                             ("flow-span", c8, "a flow collection spanning lines")):
        judge(f"tr-s-{key}", f"a second producer in a trailer-waivable region ({key}) WITH the trailer",
              *shapes["r3-" + key], needles=(shadow + where, says, "Selftest Approver"))
    judge("tr-s-trusted-ok", "the trusted workflow in its real shape, edited WITH the trailer",
          *shapes["r3-trusted-ok"], ok=True, needles=(guard + wf,), absent=(shadow,))
    judge("tr-s-amp", "other c8 jobs using &&, *) and a quoted ** (no YAML anchor or alias)", *shapes["r3-amp"],
          ok=True, absent=(shadow, guard))
    judge("tr-s-split", "a shadow name split across double-quoted line continuations", *shapes["r3-split"],
          needles=(shadow + ".github/workflows/split.yml",))
    judge("tr-s-symlink", "a symlinked workflow file WITH the trailer", *shapes["r3-symwf"],
          needles=(shadow + ".github/workflows/s.yml", "symlink"))
    judge("tr-s-notdir", ".github/workflows replaced by a file WITH the trailer", *shapes["r3-wfblob"],
          needles=(shadow + ".github/workflows", "is not a directory"))
    # #6175 (R2-3 N3/N4): U+2028 and C1 (NEL) are escaped, never printed raw.
    out = judge("tr-log-sep", "watched paths carrying U+2028 and U+0085", *shapes["r3-log-sep"],
                needles=("a\\u2028b.rs", "c\\x85d.rs"))
    if " " in out or "\x85" in out:
        t.fail("(tr-log-sep): a raw U+2028 or U+0085 reached the log:", out)
    # #6175 (R2-3 N5): `%` in a trailer is escaped inside the ::warning annotation.
    out = judge("tr-log-pct", "an approval trailer carrying %0A and a forged ::error", *shapes["r3-pct"], ok=True)
    warnings = [line for line in out.splitlines() if line.startswith("::warning title=GUARD CHANGED::")]
    if not warnings or any("%250A::error" not in w or "%0A::" in w.replace("%250A", "") for w in warnings):
        t.fail("(tr-log-pct): the ::warning line does not carry the trailer's % escaped as %25:", out)
    # #6175 (code F2 / security R2-2): an oversized workflow's file name is escaped too.
    saved_cap = globals()["MAX_BLOB_BYTES"]
    globals()["MAX_BLOB_BYTES"] = 4096
    try:
        out = judge("tr-log-big", "an oversized workflow whose name carries LF and a forged ::error",
                    *shapes["r3-bigname"], needles=("x\\x0a::error title=forged::big.yml", "exceeds 4096 bytes"),
                    absent=("(fail-closed) (fail-closed)",))
    finally:
        globals()["MAX_BLOB_BYTES"] = saved_cap
    _no_forged_lines(t, "tr-log-big", "an oversized workflow name", out)
    # R2-3 N9: inherited GIT_* variables never redirect the gate's git calls.
    planted = {"GIT_DIR": "/nonexistent", "GIT_WORK_TREE": "/nonexistent", "GIT_INDEX_FILE": "/nonexistent/index"}
    saved = {k: os.environ.get(k) for k in planted}
    os.environ.update(planted)
    try:
        judge("tr-git-env", "GIT_DIR / GIT_WORK_TREE / GIT_INDEX_FILE in the environment", *shapes["clean"], ok=True)
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


C8_GATE_LAST = "      - run: python3 -I scripts/check_cert_expiry.py\n"
TRUSTED_WF_LAST = "        run: python3 -I scripts/check_cert_expiry.py --self-test\n"


def _hidden_job(text, last, brk):
    """TEXT with SHADOW_JOB_FIXTURE joined onto its line LAST by the line break
    BRK instead of LF, so a line scan that splits on LF only sees one line."""
    return text.replace(last, last.rstrip("\n") + brk + brk.join(SHADOW_JOB_FIXTURE.rstrip("\n").split("\n")) + "\n", 1)


def _round4_shapes(shapes, pr, approve, wf_rel, c8_rel):
    """#6140 round 4 shapes (code review R3-1/R3-2, security review R3-1/R3-2,
    #6228): a second producer hidden behind a YAML line break other than LF
    inside each own job region, and one isolated shape per YAML-hazard rule."""
    named = "    name: Enterprise-federation cert-expiry gate (cert §7 / F7)\n"
    gate = "  cert-expiry-gate:\n" + named + "    runs-on: ubuntu-latest\n    steps:\n" + C8_GATE_LAST
    trusted_pr = TRUSTED_WF_FIXTURE.replace("on:\n", "on:\n  pull_request:\n", 1)
    ok_wf = "name: lb\non: [push]\njobs:\n  lb:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo lb\n"
    r4 = {
        "cr-c8": ({c8_rel: _hidden_job(C8_FIXTURE, C8_GATE_LAST, "\r")}, approve),
        "sep-c8": ({c8_rel: _hidden_job(C8_FIXTURE, C8_GATE_LAST, " ")}, approve),
        "nel-c8": ({c8_rel: _hidden_job(C8_FIXTURE, C8_GATE_LAST, "\x85")}, approve),
        "ps-c8": ({c8_rel: _hidden_job(C8_FIXTURE, C8_GATE_LAST, " ")}, approve),
        "cr-trusted": ({wf_rel: _hidden_job(trusted_pr, TRUSTED_WF_LAST, "\r")}, approve),
        "nel-trusted": ({wf_rel: _hidden_job(trusted_pr, TRUSTED_WF_LAST, "\x85")}, approve),
        "sep-trusted": ({wf_rel: _hidden_job(trusted_pr, TRUSTED_WF_LAST, "\u2028")}, approve),
        "ps-trusted": ({wf_rel: _hidden_job(trusted_pr, TRUSTED_WF_LAST, "\u2029")}, approve),
        "lb-other": ({".github/workflows/lb.yml": ok_wf.replace("on: [push]\n", "on: [push] ", 1)}, approve),
        "crlf-c8": ({c8_rel: C8_FIXTURE.replace("\n", "\r\n")}, approve),
        "merge": ({c8_rel: C8_FIXTURE.replace(named, named + "    <<: {timeout-minutes: 5}\n", 1)}, approve),
        "tag": ({c8_rel: C8_FIXTURE.replace(named, named + "    timeout-minutes: !!int 5\n", 1)}, approve),
        "blockind": ({c8_rel: C8_FIXTURE.replace(C8_GATE_LAST, C8_GATE_LAST + "      - run: |2\n          echo x\n", 1)},
                     approve),
        "docmark": ({c8_rel: "---\n" + C8_FIXTURE}, approve),
        "dupjob": ({c8_rel: C8_FIXTURE + "  cert-expiry-gate:\n    runs-on: ubuntu-latest\n    steps:\n"
                    "      - run: echo always-green\n"}, approve),
        "tab": ({c8_rel: C8_FIXTURE.replace(named, named + "    \ttimeout-minutes: 5\n", 1)}, approve),
        "qkey-hdr": ({c8_rel: C8_FIXTURE.replace("jobs:\n", '"env":\n  A: b\njobs:\n', 1)}, approve),
        "qkey-step": ({c8_rel: C8_FIXTURE.replace(C8_GATE_LAST, C8_GATE_LAST + '        "name": x\n', 1)}, approve),
        "qval": ({c8_rel: C8_FIXTURE.replace(named, named + '    env:\n      A: "x\n        y"\n', 1)}, approve),
        "qspan": ({c8_rel: C8_FIXTURE.replace(C8_GATE_LAST, C8_GATE_LAST + '      - "x\n        y"\n', 1)}, approve),
        "qmark": ({c8_rel: C8_FIXTURE.replace(named, named + "    ? shadow\n    : x\n", 1)}, approve),
        "jobs2": ({c8_rel: C8_FIXTURE + "jobs:\n  shadow2:\n    runs-on: ubuntu-latest\n    steps:\n"
                   "      - run: echo x\n"}, approve),
        "indent6": ({c8_rel: C8_FIXTURE.replace(gate, "\n".join(("  " + ln if ln.startswith("    ") else ln)
                                                                  for ln in gate.split("\n")), 1)}, approve),
        "after-block": ({c8_rel: C8_FIXTURE.replace("      - run: echo other\n",
                                                    "      - run: |\n          echo other\n", 1).replace(
            "  later-job:\n", "  later-job:\n    <<: {timeout-minutes: 5}\n", 1)}, approve),
        "window": ({".github/workflows/wide.yml": ok_wf.replace(
            "  lb:\n", '  lb:\n    name: "Enterprise-federation cert-expir\\\n      y gate"\n', 1)}, ""),
        "section": ({".github/workflows/sec.yml": ok_wf.replace(
            "  lb:\n", "  lb:\n    name: Federation gate (cert §7 / F7)\n", 1)}, ""),
    }
    for key, (edits, trailer_msg) in r4.items():
        shapes["r4-" + key] = pr("r4-" + key, edits, trailer_msg)


# Nine distinct whitespace code points: more kinds than the eight the message lists (#6556).
WS_NINE = (0xA0, 0x1680, 0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006)
# Every character str.isspace() accepts that is neither space, tab nor a YAML line break (#6555).
WS_REFUSED = (0x0B, 0x0C, 0x1C, 0x1D, 0x1E, 0x1F, 0xA0, 0x1680, *range(0x2000, 0x200B), 0x202F, 0x205F, 0x3000)

NBSP_FLOW = ("name: ws\non: [push]\njobs:\n  shadow: {{runs-on: ubuntu-latest, steps: [{{run: 'echo\n"
             "{ch}#x'}}], name: Enterprise-federation cert-expiry gate (cert \xa77 / F7)}}\n")


def _round5_shapes(shapes, pr, approve, wf_rel, c8_rel):
    """#6140 round 5 shapes (security review R4 SR4-1, #6304): Unicode
    whitespace that YAML keeps as content, leading a `#` line the scan used to
    drop as a comment, in a workflow that is not an own file and inside the
    own file c8-precheck.yml."""
    ok_wf = ("name: ws\non: [push]\njobs:\n  ws:\n    runs-on: ubuntu-latest\n"
             "    steps:\n      - run: echo ws\n")
    r5 = {
        "nbsp": ({".github/workflows/ws-nbsp.yml": NBSP_FLOW.format(ch="\u00a0")}, ""),
        "ideo": ({".github/workflows/ws-ideo.yml": NBSP_FLOW.format(ch="\u3000")}, ""),
        "ff": ({".github/workflows/ws-ff.yml": NBSP_FLOW.format(ch="\x0c")}, ""),
        "vt": ({".github/workflows/ws-vt.yml": NBSP_FLOW.format(ch="\x0b")}, ""),
        "nbsp-quoted": ({".github/workflows/ws-q.yml": ok_wf.replace(
            "echo ws", 'echo "a\u00a0b"', 1)}, ""),
        "tabcomment": ({".github/workflows/ws-tab.yml": ok_wf.replace("name: ws\n", "name: ws   \n", 1).replace(
            "jobs:\n", "\t# a tab-indented comment   \njobs:\n", 1).replace(
            "ubuntu-latest\n", "ubuntu-latest   \n", 1)}, ""),
        "nbsp-block-c8": ({c8_rel: C8_FIXTURE.replace(
            C8_GATE_LAST, C8_GATE_LAST + "      - run: |\n          echo x\n\u00a0\n          ? k\n", 1)}, approve),
        "ws-lines": ({".github/workflows/ws-lines.yml": ok_wf.replace(
            "on: [push]\n", "on: [push] #\u00a0x\n", 1).replace("  ws:\n", "  ws: #\u3000x\n", 1)}, ""),
        "ws-nine": ({".github/workflows/ws-nine.yml": "name: ws\n" + "".join(
            f"#{chr(c)}\n" for c in WS_NINE) + ok_wf.split("\n", 1)[1]}, ""),
    }
    for key, (edits, trailer_msg) in r5.items():
        shapes["r5-" + key] = pr("r5-" + key, edits, trailer_msg)


def _ws_unit_cells(t):
    """#6555: each of the 22 refused non-YAML whitespace code points has its
    own cell (`tr-s-ws-U+XXXX`), planted mid-line in a comment; U+0085, U+2028
    and U+2029 are line breaks (#6228), space and tab are YAML whitespace."""
    if len(set(WS_REFUSED)) != 22:
        t.fail(f"(tr-s-ws-all): WS_REFUSED holds {len(set(WS_REFUSED))} code points, not 22")
    for code in WS_REFUSED:
        label = f"tr-s-ws-U+{code:04X}"
        found = _whitespace_findings(".github/workflows/u.yml", f"name: u\n# a{chr(code)}b\n")
        if len(found) != 1 or f"U+{code:04X}" not in found[0]:
            t.fail(f"({label}): U+{code:04X} in a comment was not refused as that code point: {found!r}")
    for ok in (" ", "\t"):
        if _whitespace_findings(".github/workflows/u.yml", f"name: u\n# a{ok}b\n"):
            t.fail(f"(tr-s-ws-yaml): {ok!r} is YAML whitespace and must not be refused")


def _ws_format_cell(t, label, text, needles, absent=()):
    """One refusal message of _whitespace_findings for TEXT: exactly one
    finding that carries every needle and none of the absent strings."""
    found = _whitespace_findings(".github/workflows/u.yml", text)
    if len(found) != 1:
        t.fail(f"({label}): expected exactly one whitespace finding, got {found!r}")
        return
    for needle in needles:
        if needle not in found[0]:
            t.fail(f"({label}): the refusal does not say {needle!r}: {found[0]!r}")
    for needle in absent:
        if needle in found[0]:
            t.fail(f"({label}): the refusal must not say {needle!r}: {found[0]!r}")


def _ws_format_cells(t):
    """#6556 message format, pinned on direct calls of _whitespace_findings
    (#6760 one line with two refused characters, #6761 repeated code points,
    #6762 the eight-item boundary, #6763 lines are counted, not code points)."""
    # #6760: one line, two refused characters -> one line number, not one per character.
    _ws_format_cell(t, "tr-s-ws-oneline", "name: u\n# a\u00a0b\u3000c\n",
                    ("line 2 (1 in this file)", "(U+00A0, U+3000)"), absent=("lines ",))


def _ws_wording_cells(t):
    """#6554: YAML refuses FF and VT outright (PyYAML: unacceptable character),
    so a line led by one is not a second producer and YAML does not keep it as
    content; only the other Unicode spaces are kept. The refusal stays, the
    stated reason must be true. Cell `ws-wording` fails on a sentence of this
    file or of changelog.d/6304.fixed.md that says otherwise."""
    log = REPO_ROOT / "changelog.d" / "6304.fixed.md"
    flat = re.sub(r"\s*\n\s*(?:#\s*)?", " ", Path(__file__).read_text(encoding="utf-8")
                  + ("\n" + log.read_text(encoding="utf-8") if log.is_file() else ""))
    ff_vt = r"\b(?:F" + "F|V" + r"T)\b"
    wrong = (ff_vt + r"[^.;]{0,60}\b(?:keeps?|kept) as content",
             r"U\+3000, " + ff_vt + r"[^.;]{0,30}(?:and|or) (?:others|other characters) that YAML",
             r"second producer on an? [^.;\"']{0,50}" + ff_vt,
             r"second producer on a \{code\}-led",
             r"U\+3000 or F" + "F is scanned")
    for pattern in wrong:
        for hit in re.finditer(pattern, flat):
            t.fail(f"(ws-wording): FF/VT wording claims YAML keeps them or that they hide a producer: {hit.group(0)!r}")


def _trusted_round5_cells(judge, shapes):
    """#6140 round 5 (security review R4 SR4-1, #6304): the blank and comment
    tests use YAML whitespace only (space, tab), so a line led by NBSP or U+3000
    is scanned, and any other whitespace character in a workflow file (FF and
    VT included, which YAML does not load at all) is refused as GUARD SHADOW
    (RED even WITH the trailer, no waiver)."""
    shadow = "GUARD SHADOW: "
    ws = "a whitespace character other than space or tab"
    for key, code, why in (("nbsp", "U+00A0", "a second producer on a U+00A0-led line"),
                           ("ideo", "U+3000", "a second producer on a U+3000-led line"),
                           ("ff", "U+000C", "an FF-led line (not loadable YAML)"),
                           ("vt", "U+000B", "a VT-led line (not loadable YAML)")):
        judge(f"tr-s-{key}", f"{why} in a new workflow, NO trailer",
              *shapes["r5-" + key], needles=(shadow + f".github/workflows/ws-{key}.yml", ws, code,
                                              "(workflow header): names the required check"))
    judge("tr-s-nbsp-quoted", "U+00A0 only inside a quoted value of a workflow that is not an own file",
          *shapes["r5-nbsp-quoted"], needles=(shadow + ".github/workflows/ws-q.yml", ws, "U+00A0",
                                              "line 7 (1 in this file)"))
    judge("tr-s-ws-lines", "U+00A0 on line 2 and U+3000 on line 4 of a new workflow", *shapes["r5-ws-lines"],
          needles=(shadow + ".github/workflows/ws-lines.yml", ws, "lines 2, 4 (2 in this file)",
                   "(U+00A0, U+3000)"))
    judge("tr-s-ws-nine", "nine distinct whitespace code points on nine lines of a new workflow",
          *shapes["r5-ws-nine"], needles=(
              shadow + ".github/workflows/ws-nine.yml", ws, "lines 2, 3, 4, 5, 6, 7, 8, 9, +1 more (9 in this file)",
              "(U+00A0, U+1680, U+2000, U+2001, U+2002, U+2003, U+2004, U+2005, +1 more)"))
    judge("tr-s-tabcomment", "control: a tab-indented comment and trailing spaces", *shapes["r5-tabcomment"],
          ok=True, absent=(shadow,))
    judge("tr-s-nbsp-block-c8", "a U+00A0-only line ends a block scalar of c8-precheck.yml, WITH the trailer",
          *shapes["r5-nbsp-block-c8"],
          needles=(shadow + PINNED_TRUSTED_JOB[0], ws, "complex key", "Selftest Approver"))


def _trusted_round4_cells(judge, shapes):
    """#6140 round 4 (code review R3-1/R3-2, security review R3-1/R3-2, #6228):
    a second producer behind a YAML line break other than LF in an own job
    region is RED WITH the trailer (the hidden job is named, and the line
    break itself is refused in every workflow file), CRLF stays GREEN, and
    each YAML-hazard rule of the own files has a cell that isolates it."""
    shadow = "GUARD SHADOW: "
    c8, wf = PINNED_TRUSTED_JOB[0], PINNED_TRUSTED_PATHS[1]
    lb = "a YAML line break other than LF"
    for key, where in (("cr-c8", c8), ("sep-c8", c8), ("nel-c8", c8), ("ps-c8", c8),
                       ("cr-trusted", wf), ("nel-trusted", wf), ("sep-trusted", wf), ("ps-trusted", wf)):
        # The trusted workflow is guarded whole, so its edit also prints the waived GUARD CHANGED.
        judge(f"tr-s-{key}", f"a second producer behind a non-LF YAML line break ({key}) WITH the trailer",
              *shapes["r4-" + key], needles=(shadow + where, lb, "(job 'shadow')")
              + (("Selftest Approver",) if where == wf else ()))
    judge("tr-s-lb-other", "a YAML line break other than LF in a workflow that is not an own file",
          *shapes["r4-lb-other"], needles=(shadow + ".github/workflows/lb.yml", lb))
    judge("tr-s-crlf", "c8-precheck.yml with CRLF line ends WITH the trailer", *shapes["r4-crlf-c8"], ok=True,
          absent=(shadow,))
    for key, says in (("merge", "merge key"), ("tag", "a YAML tag"), ("blockind", "indentation indicator"),
                      ("docmark", "document marker"), ("dupjob", "is defined twice"),
                      ("tab", "a tab in the indentation"), ("qkey-hdr", "a quoted mapping key"),
                      ("qkey-step", "a quoted mapping key"), ("qval", "a quoted scalar spanning lines"),
                      ("qspan", "a quoted scalar spanning lines"), ("qmark", "complex key"),
                      ("jobs2", "a second jobs: key"), ("indent6", "is not indented by 4 spaces")):
        judge(f"tr-s-{key}", f"an own-file YAML hazard ({key}) WITH the trailer", *shapes["r4-" + key],
              needles=(shadow + c8, says, "Selftest Approver"))
    # The hazard scan resumes after a block scalar: a merge key in a later (unguarded) job is refused.
    judge("tr-s-after-block", "a merge key in a c8 job after a `run: |` block", *shapes["r4-after-block"],
          needles=(shadow + c8, "merge key"))
    judge("tr-s-window", "a name fragment split by a quoted continuation after 9 of its characters",
          *shapes["r4-window"], needles=(shadow + ".github/workflows/wide.yml",))
    judge("tr-s-section", "a name carrying only the section-sign fragment", *shapes["r4-section"],
          needles=(shadow + ".github/workflows/sec.yml",))


# The fetch timeout and the job budget it must fit (code F3, security R2-4).
PINNED_FETCH_TIMEOUT = 45
TRUSTED_JOB_SECONDS = 600
GIT_HANG_SHIM = """#!{python}
import os, sys, time
real, argv = {real!r}, sys.argv[1:]
if {hang!r} in argv:
    time.sleep(30)
os.execv(real, [real] + argv)
"""

GIT_STDERR_SHIM = """#!{python}
import os, sys
real, argv = {real!r}, sys.argv[1:]
if "fetch" in argv:
    sys.stderr.buffer.write(b"fatal: remote says \\xe2\\x80\\xa8\\x1b[31m\\n::error title=forged::x\\n")
    sys.exit(1)
os.execv(real, [real] + argv)
"""


@contextlib.contextmanager
def _git_shim(tmp, template, **fields):
    """PATH-shim `git` from TEMPLATE (GIT_SHIM or GIT_HANG_SHIM) for the block."""
    real = shutil.which("git")
    if real is None:
        raise GateError("git is not on PATH")
    shim_dir = Path(tempfile.mkdtemp(prefix="gitshim.", dir=str(tmp)))
    shim = shim_dir / "git"
    shim.write_text(template.format(python=sys.executable, real=real, **fields), encoding="utf-8")
    shim.chmod(0o755)
    saved = os.environ.get("PATH")
    os.environ["PATH"] = f"{shim_dir}{os.pathsep}{saved or ''}"
    try:
        yield
    finally:
        if saved is None:
            os.environ.pop("PATH", None)
        else:
            os.environ["PATH"] = saved
        shutil.rmtree(shim_dir, ignore_errors=True)


def _trusted_round3_fetch_cells(tmp, t, fx, mirror, head8, good8):
    """#6140 round 3 (code F3, security R2-3 N7, R2-4, R2-5): every fetch is
    time-bounded within the job timeout, a failed fetch is reported with its
    error text, a failed head fetch stops before any merge fetch, and a
    destination ref left by an earlier run is never judged."""
    fetch_timeout = globals().get("FETCH_TIMEOUT")
    if fetch_timeout != PINNED_FETCH_TIMEOUT:
        t.fail(f"(tr-f-pin): FETCH_TIMEOUT {fetch_timeout!r} differs from {PINNED_FETCH_TIMEOUT!r}")
    worst = (len(PINNED_MERGE_REF_SLEEPS) + 2) * PINNED_FETCH_TIMEOUT + sum(PINNED_MERGE_REF_SLEEPS)
    if worst > TRUSTED_JOB_SECONDS - 180:
        t.fail(f"(tr-f-pin): worst-case fetch time {worst} s leaves under 180 s of the {TRUSTED_JOB_SECONDS} s job")
    real_run_git, real_sleep, fetches, cut = globals()["run_git"], globals().get("_sleep"), [], {}

    def recording_run_git(repo, *args, **kw):
        if "fetch" in args:
            fetches.append((args, kw.get("timeout")))
            # tr-f-hang: the hung refspec is cut sooner, only once the gate passed FETCH_TIMEOUT
            # (the other fetches keep the real bound, so a slow host never fails them).
            if fetch_timeout is not None and kw.get("timeout") == fetch_timeout and any(s in args for s in cut):
                kw["timeout"] = cut[next(spec for spec in cut if spec in args)]
        return real_run_git(repo, *args, **kw)

    def run(label, why, ok, needles=(), absent=(), pr_number="7", merge_ref="refs/remotes/pull/m7"):
        del fetches[:]
        rc, out = trusted_cli(mirror, "--base-ref=main", f"--head-sha={head8}", f"--pr-number={pr_number}",
                              f"--merge-ref={merge_ref}")
        if (rc == 0) != ok or rc not in (0, 1):
            t.fail(f"({label}): {why}: rc {rc}, expected {0 if ok else 1}:", out)
        for needle in needles:
            if needle not in out:
                t.fail(f"({label}): {why}: output does not say {needle!r}:", out)
        for needle in absent:
            if needle in out:
                t.fail(f"({label}): {why}: output must not say {needle!r}:", out)
        return out

    def ref_of(ref):
        proc = run_git(mirror, "rev-parse", "--verify", "--quiet", ref)
        return proc.stdout.decode().strip() if proc.returncode == 0 else ""

    globals()["run_git"], globals()["_sleep"] = recording_run_git, lambda seconds: None
    try:
        fx.g("update-ref", "refs/pull/7/head", head8)
        fx.g("update-ref", "refs/pull/7/merge", good8)
        run("tr-f-timeout", "a current merge ref", True)
        if not fetches or any(timeout != fetch_timeout for _, timeout in fetches):
            t.fail(f"(tr-f-timeout): a git fetch ran without the FETCH_TIMEOUT bound: {fetches!r}")
        # R2-5: a merge ref an earlier run left behind is deleted before the fetch, never judged.
        fx.g("update-ref", "-d", "refs/pull/7/merge")
        Fixture(mirror).g("update-ref", "refs/remotes/pull/m7", good8)
        run("tr-f-stale-local", "a current local merge ref with none on the origin", False,
            needles=("::error title=cert-expiry trusted::", "missing", "last fetch error"))
        # R2-3 N7: no refs/pull/9/head on the origin: fail closed before any merge fetch.
        run("tr-f-head", "a pull request head the origin does not have", False, pr_number="9",
            needles=("::error title=cert-expiry trusted::", "git fetch of refs/pull/9/head"))
        if any("+refs/pull/9/merge:refs/remotes/pull/m7" in args for args, _ in fetches):
            t.fail(f"(tr-f-head): a merge fetch ran after the head fetch failed: {fetches!r}")
        if ref_of(HEAD_FETCH_REF) or ref_of("refs/remotes/pull/m7"):
            t.fail("(tr-f-head): a destination ref from an earlier fetch survived a failed fetch")
        # Code F3: the last fetch error is part of the ::error.
        fx.g("update-ref", "refs/pull/7/merge", good8)
        with _git_shim(tmp, GIT_SHIM, version="", fail="+refs/pull/7/merge:refs/remotes/pull/m7", trace=""):
            run("tr-f-error", "every merge fetch failing", False,
                needles=("::error title=cert-expiry trusted::", "last fetch error", "shim refuses"))
        # R2-4: a hung fetch is cut at its timeout and retried, then reported as an ::error.
        hang = "+refs/pull/7/merge:refs/remotes/pull/m7"
        cut[hang] = 1
        try:
            with _git_shim(tmp, GIT_HANG_SHIM, hang=hang):
                run("tr-f-hang", "every merge fetch hanging", False,
                    needles=("::error title=cert-expiry trusted::", "last fetch error", "could not complete"))
        finally:
            cut.clear()
        # Round 4 (code R3-2 X12, security R3-2 Q10): a failed `update-ref -d` stops before any fetch.
        with _git_shim(tmp, GIT_SHIM, version="", fail="update-ref", trace=""):
            run("tr-f-delete", "every destination-ref delete failing", False,
                needles=("git update-ref -d", "shim refuses"))
        if fetches:
            t.fail(f"(tr-f-delete): a fetch ran after a failed update-ref -d: {fetches!r}")
        # Round 4 (code R3-2 X14): git's fetch stderr is escaped, never printed raw.
        with _git_shim(tmp, GIT_STDERR_SHIM):
            out = run("tr-f-stderr", "a fetch whose stderr carries U+2028, ESC, LF and a forged ::error", False,
                      needles=("\\u2028", "\\x1b[31m", "\\x0a::error title=forged"))
        if "\u2028" in out or "\x1b" in out:
            t.fail("(tr-f-stderr): a raw U+2028 or ESC from git's stderr reached the log:", out)
        _no_forged_lines(t, "tr-f-stderr", "git's fetch stderr", out)
    finally:
        globals()["run_git"] = real_run_git
        if real_sleep is None:
            globals().pop("_sleep", None)
        else:
            globals()["_sleep"] = real_sleep


# The functions of this file that format GIT_SHIM for a trusted-mode cell (#6550).
TRACE_SHIM_SITES = ("_trusted_round3_fetch_cells", "trusted_cli_shimmed")


def _shim_trace_cells(t):
    """#6550: a sibling change adds a `trace` field to GIT_SHIM, and a template
    field with no value raises KeyError at format time. Every trusted-mode
    site that fills GIT_SHIM names `trace=` so the template keeps formatting
    whichever side lands first (cell `shim-trace`)."""
    import ast
    tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
    seen = 0
    for func in ast.walk(tree):
        if not isinstance(func, ast.FunctionDef) or func.name not in TRACE_SHIM_SITES:
            continue
        for call in ast.walk(func):
            if not isinstance(call, ast.Call):
                continue
            fn = call.func
            formats = (isinstance(fn, ast.Attribute) and fn.attr == "format"
                       and isinstance(fn.value, ast.Name) and fn.value.id == "GIT_SHIM")
            wraps = (isinstance(fn, ast.Name) and fn.id == "_git_shim" and len(call.args) > 1
                     and isinstance(call.args[1], ast.Name) and call.args[1].id == "GIT_SHIM")
            if not (formats or wraps):
                continue
            seen += 1
            if "trace" not in {kw.arg for kw in call.keywords}:
                t.fail(f"(shim-trace): {func.name} line {call.lineno} fills GIT_SHIM without trace=")
    if seen != 3:
        t.fail(f"(shim-trace): expected 3 GIT_SHIM sites in {TRACE_SHIM_SITES}, found {seen}")


def trusted_cli_shimmed(tmp, repo, fail, shape):
    """trusted_cli on SHAPE (head, merge) with a PATH shim git that exits 128
    on any call whose argv contains FAIL (a read error on a missing object)."""
    real = shutil.which("git")
    if real is None:
        return 2, "git is not on PATH"
    shim_dir = Path(tempfile.mkdtemp(prefix="gitshim.", dir=str(tmp)))
    shim = shim_dir / "git"
    shim.write_text(GIT_SHIM.format(python=sys.executable, real=real, version="", fail=fail, trace=""),
                    encoding="utf-8")
    shim.chmod(0o755)
    saved = os.environ.get("PATH")
    os.environ["PATH"] = f"{shim_dir}{os.pathsep}{saved or ''}"
    try:
        return trusted_cli(repo, "--base-ref=main", f"--head-sha={shape[0]}", f"--merge-ref={shape[1]}")
    finally:
        if saved is None:
            os.environ.pop("PATH", None)
        else:
            os.environ["PATH"] = saved
        shutil.rmtree(shim_dir, ignore_errors=True)


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
    "error fail-closed; "
    "(pr4-reversed) reversed parents RED; (pr5) stale branch without a wire change "
    "over a base that gained one GREEN; (pr6) PR wire change without a banner flip RED; "
    "(pr7) merge with an unrelated branch (second parent is not the PR head) RED and an "
    "octopus merge RED; (ci1-ci7, #5970) the event payload range is authoritative under "
    "GitHub Actions and CERT_EXPIRY_BASE/HEAD overrides are refused there but honoured "
    "outside CI; (shim-isolation, #6145) the git PATH shim runs under python3 -I: isolated flag set and "
    "a module planted beside it not importable, checked before any shimmed gate run; "
    "(shim-interpreter, #6145) a whitespace, NUL, over-long (>255 byte) or non-UTF-8 interpreter line is "
    "refused and a 255-byte line is accepted; (shim-interpreter-robust, #6145) a missing or near-PATH_MAX "
    "scratch dir, sized from the platform PATH_MAX, yields a named violation, not a traceback; "
    "(shim-deep-scratch, #6145) the deep scratch builder lands on the exact length, removes itself on failure and "
    "a build failure is a named violation; (shim-unexecutable, #6145) an unexecutable shim "
    "is reported as a violation; (path-max-fallback, #6145) PATH_MAX falls back to 1024 on macOS/BSD and "
    "4096 elsewhere when os.pathconf fails; (guarded, #6145) a crashing cell becomes a named failure and "
    "KeyboardInterrupt propagates; (shim-scratch-limit, #6145) a too-deep scratch path is reported with its "
    "length and the limit; (shim-deep-relative, #6145) the deep-scratch targets stay valid on a deep checkout; "
    "(shim-deep-cap, #6145) they stay inside [deep_scratch base, PATH_MAX-1] and a scratch 24 bytes under "
    "PATH_MAX gets the 'needs room' message; (path-max-restore, #6145) os.pathconf and sys.platform are "
    "restored and the fallback check runs once, first; (path-max-diagnostic, #6145) a dropped restore "
    "names the real host platform and is put back, and a failing (not leaking) fallback check is "
    "reported as path-max-fallback, running only that cell in the same scratch dir; "
    "(shim-isolation-crash, #6145) a crash in the isolation cell is a named failure; "
    "(checkout-depth-coverage, #6145) checkout-depth runs the shim-unexecutable cell; "
    "(checkout-depth, #6145) every #6145 shim and scratch cell (including shim-unexecutable) passes in a "
    "226-byte scratch dir, the one a 184-byte checkout gets; the gate-run fixtures build one gitshim.* level under the scratch "
    "dir and fit within it; "
    "(tr, #6140) --trusted mode over a BARE mirror (objects only, nothing checked out): "
    "a head that stubs the gate to exit 0 and changes the wire RED with the §7 sentence and GUARD "
    "CHANGED (the stub itself exits 0), a trailer never waives §7, environment overrides ignored, "
    "each trusted path and the cert-expiry-gate job block RED without the trailer and GREEN with it, "
    "other c8 jobs GREEN, a symlinked cert doc fail-closed, and the merge-parent cells (second "
    "parent, octopus, reversed, not a merge, moved base GREEN, off-base) plus argument refusals; "
    "(tr round 2) each c8-precheck.yml header key (env, on, permissions, defaults) RED without the "
    "trailer and GREEN with it plus a ::warning annotation, a git ls-tree read error fail-closed "
    "(entry, banner, guard, end to end), a cert doc above the blob cap refused, and a shadow job "
    "producing the required check name (c8, new file, copied workflow, YAML escapes, folded scalar) "
    "RED even with the trailer while an unrelated new workflow stays GREEN; "
    "(tr #6176) --pr-number fetches the merge ref itself: current GREEN with no sleep, current on the "
    "second fetch GREEN after one fixed sleep, stale or missing (conflicted) RED with an ::error after "
    "the fixed backoff, malformed numbers and a sha --merge-ref refused; (tr #6175) a watched path, a "
    "workflow file name and an approval trailer carrying LF / CR and a forged ::error printed escaped, "
    "with no log line read as a workflow command; (tr round 3) a second producer in the trusted "
    "workflow, behind a quoted or flow job key, through a YAML anchor / alias (job, header, env), as the "
    "trusted job's name, in the trusted or the c8-precheck.yml header, or as an anchor inside a flow "
    "collection RED even with the trailer, a flow collection spanning lines refused, while the real trusted shape "
    "edited with the trailer and c8 jobs using &&, *) and ** stay GREEN; a name split across quoted "
    "continuations, a symlinked workflow and a non-directory .github/workflows RED; U+2028, C1, % and an "
    "oversized workflow's name escaped; inherited GIT_* ignored; every fetch bounded by FETCH_TIMEOUT within "
    "the job, a failed or hung fetch an ::error naming the last fetch error, a failed head fetch stopping "
    "before any merge fetch, and a destination ref from an earlier run deleted, never judged; (tr round 4, "
    "#6228) a second producer joined to an own job line by a CR, LS, PS or NEL RED even with the trailer (the "
    "hidden job named, the line break refused in every workflow file) while CRLF stays GREEN; a merge key, tag, "
    "explicit block indentation indicator, document marker, duplicate job, tab, quoted key (header or step), "
    "quoted scalar spanning lines (value or node), complex key, second jobs: key, an own job body not indented "
    "by 4 and a merge key after a block scalar each RED with the trailer; a name fragment split after 9 "
    "characters and a section-sign-only fragment RED; a failed update-ref -d stopping before any fetch and "
    "git's fetch stderr escaped; (tr round 5, #6304) a second producer on a NBSP or U+3000 led line, "
    "and an FF or VT led line (not loadable YAML), of a new workflow, a Unicode whitespace character only inside a quoted value, and a "
    "NBSP-only line ending a block scalar of c8-precheck.yml RED (no trailer needed; not waivable) "
    "while a tab-indented comment and trailing spaces stay GREEN; (tr round 5, #6228) a second producer "
    "joined by LS or PS in the trusted workflow RED with the trailer, and a hostile workflow file "
    "name printed escaped by both the line-break and the shadow messages."
)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Enterprise-federation certification section 7 expiry gate.")
    parser.add_argument("--self-test", action="store_true",
                        help="plant-a-violation corpus in a scratch repository")
    parser.add_argument("--trusted", action="store_true",
                        help="judge a pull_request merge commit from git objects only "
                             "(the pull_request_target base-copy job, #6140)")
    parser.add_argument("--repo", default=str(REPO_ROOT), help="--trusted: repository to read")
    parser.add_argument("--base-ref", help="--trusted: the pull request base branch name")
    parser.add_argument("--base-sha", default="", help="--trusted: payload base sha (report-only)")
    parser.add_argument("--head-sha", help="--trusted: the pull request head sha")
    parser.add_argument("--merge-ref", help="--trusted: the merge commit (sha or refs/remotes/ ref)")
    parser.add_argument("--pr-number", help="--trusted: fetch refs/pull/<N>/merge into --merge-ref with "
                                            "bounded re-fetch (#6176)")
    args = parser.parse_args(argv)
    if args.trusted and args.self_test:
        parser.error("--trusted and --self-test are exclusive")
    if args.trusted:
        missing = [f"--{n.replace('_', '-')}" for n in ("base_ref", "head_sha", "merge_ref")
                   if getattr(args, n) is None]
        if missing:
            parser.error(f"--trusted requires {', '.join(missing)}")
    elif args.base_sha or any(v is not None for v in (args.base_ref, args.head_sha, args.merge_ref,
                                                      args.pr_number)):
        parser.error("--base-ref/--base-sha/--head-sha/--merge-ref/--pr-number are only valid with --trusted")
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    if args.self_test:
        return self_test()
    if args.trusted:
        rc, out, err = run_trusted(Path(args.repo), args.base_ref, args.head_sha,
                                   args.merge_ref, args.base_sha, args.pr_number)
    else:
        rc, out, err = run_gate(REPO_ROOT, dict(os.environ))
    if out:
        print(out)
    if err:
        print(err, file=sys.stderr)
    return rc


if __name__ == "__main__":
    sys.exit(main())
