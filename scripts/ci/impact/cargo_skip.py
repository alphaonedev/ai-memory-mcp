"""Decide whether the cargo matrix legs can no-op for a PR diff (#8322).

The classify job feeds the changed paths in and appends the printed lines to
GITHUB_OUTPUT:

    docs_only=<true|false>          tightened: docs no Rust test reads
    cargo_skip=<true|false>         superset of docs_only: also scripts/ci/tests/**
    cargo_skip_reason=<one line>    names the verdict and the rules version

    git diff --no-renames --name-only <base> HEAD | \\
        python3 -I scripts/ci/impact/cargo_skip.py --stdin
    python3 -I scripts/ci/impact/cargo_skip.py --repo . --base <sha> --head <sha>

The skip set lives in rules.json under "cargo_skip" and is the ONLY source: the
workflow reads it through this module and the guard test
(its file name carries the issue number, under scripts/ci/tests) proves that no path a Rust
test or source file can open is inside it. A path is skippable only when it
matches a skip glob and matches neither a never-skip glob nor a test-read glob.
Anything unexpected (no paths, unreadable rules, a git error) fails closed:
both verdicts false.

Symlink rules (#8493). The globs match file NAMES only, so a symlink would hide
an edit to its target from every glob. Two checks run before any docs-only or
skip verdict, with the --repo directory as the tree:

1. Tracked symlinks anywhere in the work tree force full CI. The top of the
   work tree is resolved with `git -C <repo> rev-parse --absolute-git-dir
   --show-toplevel` and scanned whatever --repo names inside it, as
   `git --git-dir=<gitdir> --work-tree=<top>` (never re-discovered at the top),
   from two listings: the index
   (`git ls-files -s -z`) and the committed tree (`git ls-tree -r -z HEAD`).
   The index is scanned first, so a symlink found there is reported before the
   HEAD-tree listing runs. A mode 120000 entry in either gives both verdicts
   false with reason tracked-symlink-full-ci naming the first path. A mode
   160000 entry (a gitlink; no submodule checkout is needed) is treated the
   same way with reason tracked-gitlink-full-ci, so a gitlink under a docs glob
   cannot keep a docs-only verdict. This costs a full run even for a symlink
   outside every test_read_globs entry; the classifier never expands a
   wildcard glob or walks the tree. Every git call runs with the
   repository-locating variables of `git rev-parse --local-env-vars` removed
   from its environment (GIT_LOCAL_ENV_VARS), so an inherited GIT_DIR,
   GIT_WORK_TREE or GIT_INDEX_FILE cannot point the scan at another
   repository.
2. Defence in depth: a path named by test_read_globs (the literal path, or the
   literal directory prefix of a wildcard glob) that is a symlink in the
   working tree (lstat, never followed) gives both false with reason
   registered-read-path-is-symlink-full-ci naming the path. This catches a
   link the index does not know about. Untracked paths below a wildcard tail
   are NOT walked or checked.

A missing path is not a symlink and keeps the normal verdict. A bare
repository, a directory that is not a repository, git missing, a git timeout
or a nonzero git exit all fail closed: both verdicts false with reason
classifier-error-fail-closed carrying the return code and the head of stderr.
An unborn HEAD with no staged symlink or gitlink (nothing staged, or only
regular files) takes that path (the HEAD-tree listing exits nonzero); an
unborn HEAD with a staged symlink or gitlink reports tracked-symlink-full-ci
or tracked-gitlink-full-ci instead, because the index scan finds it
before the HEAD-tree listing runs.
"""
import argparse
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

# Appended, never first: a scripts/ci module named like a stdlib module must not
# shadow it (security F1, #8328). The workflow also runs this file from the base
# tree, so the PR head cannot supply the decider at all.
sys.path.append(str(Path(__file__).resolve().parents[1]))

from impact import common  # noqa: E402

SECTION = "cargo_skip"
GIT_TIMEOUT_S = 120
TRUE = "true"
FALSE = "false"
REASON_EMPTY = "empty-diff-fail-closed"
REASON_ERROR = "classifier-error-fail-closed"
REASON_DOCS = "docs-only"
REASON_TESTS = "no-rust-observable-paths"
REASON_RUST = "rust-observable-path"
REASON_EVENT = "push-event-full-ci"
REASON_MERGE_GROUP = "merge-group-full-ci"
REASON_BASE = "protected-base-full-ci"
REASON_CI_TREE = "ci-tree-edited-full-ci"
REASON_SYMLINK = "registered-read-path-is-symlink-full-ci"
REASON_TRACKED_SYMLINK = "tracked-symlink-full-ci"
REASON_TRACKED_GITLINK = "tracked-gitlink-full-ci"
GIT_SYMLINK_MODE = "120000"
GIT_GITLINK_MODE = "160000"
GIT_FORCED_MODES = {GIT_SYMLINK_MODE: REASON_TRACKED_SYMLINK,
                    GIT_GITLINK_MODE: REASON_TRACKED_GITLINK}
# Source: the output of `git rev-parse --local-env-vars` (git 2.43). These are the
# variables that locate or reshape a repository; a caller must not steer the
# classifier's git calls with them. A test pins the list against the host git.
GIT_LOCAL_ENV_VARS = frozenset((
    "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_CONFIG", "GIT_CONFIG_PARAMETERS",
    "GIT_CONFIG_COUNT", "GIT_OBJECT_DIRECTORY", "GIT_DIR", "GIT_WORK_TREE",
    "GIT_IMPLICIT_WORK_TREE", "GIT_GRAFT_FILE", "GIT_INDEX_FILE",
    "GIT_NO_REPLACE_OBJECTS", "GIT_REPLACE_REF_BASE", "GIT_PREFIX",
    "GIT_SHALLOW_FILE", "GIT_COMMON_DIR"))
STDERR_HEAD_CHARS = 120
PRINTABLE_ASCII = re.compile(r"[^\x20-\x7e]")
GLOB_WILDCARDS = frozenset("*?[")
GLOB_LISTS = ("skip_globs", "docs_globs", "never_skip_globs", "test_read_globs",
              "ci_tree_globs", "ci_tree_exempt_globs", "full_ci_events",
              "full_ci_base_names", "full_ci_base_prefixes")


def load_section(rules_path: Optional[Path] = None) -> dict:
    """Return the validated cargo_skip section of rules.json."""
    section = common.load_rules(rules_path)[SECTION]
    for key in ("version", "walk_guards") + GLOB_LISTS:
        if key not in section:
            raise ValueError("rules.json cargo_skip lacks %s" % key)
    guards = section["walk_guards"]
    if not isinstance(guards, list) or not all(
            isinstance(g, dict) and {"rust", "guard", "roots"} <= set(g) for g in guards):
        raise TypeError("rules.json cargo_skip.walk_guards must list rust/guard/roots objects")
    for key in GLOB_LISTS:
        value = section[key]
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            raise TypeError("rules.json cargo_skip.%s must be a list of strings" % key)
    return section


def matches_any(globs: Iterable[str], path: str) -> bool:
    """Return True when `path` matches any glob."""
    return any(common.match_glob(glob, path) for glob in globs)


def guard_paths(section: dict) -> List[str]:
    """Return the walk-guard test paths: the files that stand in for a skipped Rust test."""
    return [guard["guard"] for guard in section["walk_guards"]]


def blocked(section: dict, path: str) -> bool:
    """Return True when `path` can never be skipped (never-skip, test-read or a walk guard).

    A walk guard is derived here as well as listed in never_skip_globs: the
    file that replaces a skipped Rust test must never be skippable itself
    (REVIEW-8328-code-r2 F3).
    """
    return (matches_any(section["never_skip_globs"], path)
            or matches_any(section["test_read_globs"], path)
            or path in guard_paths(section))


def is_doc(section: dict, path: str) -> bool:
    """Return True for a documentation path no test reads."""
    return matches_any(section["docs_globs"], path) and not blocked(section, path)


def is_skippable(section: dict, path: str) -> bool:
    """Return True when changing `path` cannot change any cargo leg's result."""
    return matches_any(section["skip_globs"], path) and not blocked(section, path)


def literal_prefixes(glob: str) -> List[str]:
    """Return the cumulative literal path prefixes of `glob`, never walking the tree.

    "docs/ADMIN_GUIDE.md" gives ["docs", "docs/ADMIN_GUIDE.md"]; the wildcard
    glob "docs/compliance/**" gives ["docs", "docs/compliance"]; "**/README.md"
    gives [].
    """
    prefixes: List[str] = []
    parts: List[str] = []
    for part in glob.split("/"):
        if GLOB_WILDCARDS & set(part):
            break
        parts.append(part)
        prefixes.append("/".join(parts))
    return prefixes


def symlinked_read_path(section: dict, repo: Path) -> Optional[str]:
    """Return the first test_read_globs path that is a symlink under `repo`, else None.

    Uses lstat via Path.is_symlink (the link is never followed); a missing path
    is not a symlink.
    """
    for glob in section["test_read_globs"]:
        for prefix in literal_prefixes(glob):
            if (repo / prefix).is_symlink():
                return prefix
    return None


def git_environment(base: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """Return a copy of `base` (default os.environ) without GIT_LOCAL_ENV_VARS.

    PATH and every other variable stay, so git missing from PATH still fails closed.
    """
    source = os.environ if base is None else base
    return {k: v for k, v in source.items() if k not in GIT_LOCAL_ENV_VARS}


def git_output(repo: Optional[Path], args: List[str], what: str) -> bytes:
    """Return stdout of `git [-C <repo>] <args>`; raise RuntimeError on any failure.

    `repo` None runs git without -C (the caller supplies --git-dir/--work-tree).

    The message carries `what`, the return code and a sanitised head of stderr
    (one printable line); git missing or timing out is the same error path.
    """
    dash_c = [] if repo is None else ["-C", str(repo)]
    try:
        res = subprocess.run(["git"] + dash_c + args,
                             capture_output=True, timeout=GIT_TIMEOUT_S,
                             env=git_environment())
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError("%s did not run: %s" % (what, clean_text(str(exc)))) from exc
    if res.returncode != 0:
        head = clean_text(res.stderr.decode("utf-8", "replace"))
        raise RuntimeError("%s rc=%d %s" % (what, res.returncode, head))
    return res.stdout


def first_forced_entry(listing: bytes) -> Optional[Tuple[str, str]]:
    """Return (reason, path) of the first mode 120000 or 160000 entry of a listing.

    The listing is NUL-separated.

    Both `ls-files -s -z` and `ls-tree -r -z` put the mode first, then a TAB
    before the path.
    """
    for entry in listing.split(common.NUL.encode()):
        meta, _, path = entry.partition(b"\t")
        reason = GIT_FORCED_MODES.get(meta.split(b" ", 1)[0].decode("ascii", "replace"))
        if reason:
            return reason, path.decode("utf-8", "replace")
    return None


def tracked_symlink(repo: Path) -> Optional[Tuple[str, str]]:
    """Return (reason, path) of the first tracked symlink or gitlink around `repo`.

    The git dir and the top of the work tree are resolved in ONE call
    (`rev-parse --absolute-git-dir --show-toplevel`, two output lines), so the
    scan covers the whole tree whatever --repo names inside it and trusts only
    the repository --repo resolved to: both listings run as
    `git --git-dir=<gitdir> --work-tree=<top>` (no -C), so a repository found
    at the top, or a core.worktree pointing elsewhere, is never consulted. Each
    path is taken byte for byte from git (only the one trailing newline is
    removed; a name ending in a space, tab or CR keeps it). Two listings are
    scanned: the index (`ls-files -s -z`) and the committed tree
    (`ls-tree -r -z HEAD`), so a missing or empty index cannot hide a symlink
    HEAD tracks. Raises RuntimeError when git is missing, times out or exits
    nonzero: a bare repository, a directory that is not a repository and an
    unborn HEAD with nothing staged as a symlink or gitlink all fail closed.
    """
    raw = git_output(repo, ["rev-parse", "--absolute-git-dir", "--show-toplevel"],
                     "git rev-parse")
    lines = raw.removesuffix(b"\n").split(b"\n")
    if len(lines) != 2:
        raise RuntimeError("git rev-parse returned %d lines, expected 2" % len(lines))
    git_dir, top = (line.decode("utf-8", "surrogateescape") for line in lines)
    scope = ["--git-dir=" + git_dir, "--work-tree=" + top]
    for args, what in ((["ls-files", "-s", "-z"], "git ls-files"),
                       (["ls-tree", "-r", "-z", "HEAD"], "git ls-tree")):
        found = first_forced_entry(git_output(None, scope + args, what))
        if found:
            return found
    return None


def clean_text(text: str) -> str:
    """Return `text` cut to STDERR_HEAD_CHARS with every non-printable byte replaced."""
    return PRINTABLE_ASCII.sub("?", text.strip())[:STDERR_HEAD_CHARS]


def full_ci_reason(section: dict, event_name: str, base_ref: str) -> Optional[str]:
    """Return the reason a run must be full whatever the diff, else None.

    Every push event and every pull request into a protected base (release
    branches, main, develop) runs the whole pipeline (3-agent vote 6def5ab6
    point 7; code review r1 F2, #8328).
    """
    if event_name in section["full_ci_events"]:
        return REASON_MERGE_GROUP if event_name == "merge_group" else REASON_EVENT
    if base_ref and (base_ref in section["full_ci_base_names"]
                     or any(base_ref.startswith(p)
                            for p in section["full_ci_base_prefixes"])):
        return REASON_BASE
    return None


def classify(section: dict, paths: List[str], event_name: str = "",
             base_ref: str = "", repo: Optional[Path] = None) -> Dict[str, str]:
    """Return the three output values for the changed `paths`.

    With `repo` set, any tracked symlink, any tracked gitlink or a symlinked
    test_read_globs path forces cargo (#8493); a git failure fails closed.
    """
    version = "cargo_skip-rules-v%s" % section["version"]
    forced = full_ci_reason(section, event_name, base_ref)
    if forced:
        return verdict(FALSE, FALSE, "%s %s" % (forced, version))
    if not paths:
        return verdict(FALSE, FALSE, "%s %s" % (REASON_EMPTY, version))
    if repo is not None:
        try:
            tracked = tracked_symlink(repo)
        except RuntimeError as exc:
            return verdict(FALSE, FALSE, "%s %s %s" % (REASON_ERROR, exc, version))
        if tracked:
            return verdict(FALSE, FALSE, "%s %s %s" % (
                tracked[0], clean_text(tracked[1]), version))
        linked = symlinked_read_path(section, repo)
        if linked:
            return verdict(FALSE, FALSE, "%s %s %s" % (REASON_SYMLINK, linked, version))
    for path in paths:
        if (matches_any(section["ci_tree_globs"], path)
                and not matches_any(section["ci_tree_exempt_globs"], path)):
            return verdict(FALSE, FALSE, "%s %s %s" % (REASON_CI_TREE, path, version))
    docs_only = all(is_doc(section, p) for p in paths)
    skip = all(is_skippable(section, p) for p in paths)
    if docs_only:
        return verdict(TRUE, TRUE, "%s %s" % (REASON_DOCS, version))
    if skip:
        return verdict(FALSE, TRUE, "%s %s" % (REASON_TESTS, version))
    first = next(p for p in paths if not is_skippable(section, p))
    return verdict(FALSE, FALSE, "%s %s %s" % (REASON_RUST, first, version))


def verdict(docs_only: str, cargo_skip: str, reason: str) -> Dict[str, str]:
    """Build the output mapping (reason is one line, no newline)."""
    return {"docs_only": docs_only, "cargo_skip": cargo_skip,
            "cargo_skip_reason": reason.replace("\n", " ")}


def diff_paths(repo: Path, base: str, head: str) -> List[str]:
    """Return the changed paths (old paths of renames included)."""
    res = subprocess.run(
        ["git", "diff", "--no-renames", "--name-only", "-z", base, head],
        cwd=str(repo), capture_output=True, timeout=GIT_TIMEOUT_S,
        env=git_environment())
    if res.returncode != 0:
        raise RuntimeError("git diff failed")
    return [p.decode("utf-8", "surrogateescape")
            for p in res.stdout.split(common.NUL.encode()) if p]


def stdin_paths(text: str) -> List[str]:
    """Return the non-empty lines of `text`."""
    return [line for line in text.splitlines() if line]


def emit(values: Dict[str, str]) -> None:
    """Print the output lines in a fixed order."""
    for key in ("docs_only", "cargo_skip", "cargo_skip_reason"):
        print("%s=%s" % (key, values[key]))


def main(argv: Optional[List[str]] = None) -> int:
    """Classify the diff; exit 0 with a fail-closed verdict on error, 1 on a bad rules shape."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--rules", default=str(common.RULES_PATH))
    parser.add_argument("--repo", default=".")
    parser.add_argument("--base")
    parser.add_argument("--head", default="HEAD")
    parser.add_argument("--stdin", action="store_true",
                        help="read newline-separated changed paths from stdin")
    parser.add_argument("--event-name", default="",
                        help="github.event_name; a push always runs the full pipeline")
    parser.add_argument("--base-ref", default="",
                        help="github.base_ref; release/*, main and develop run in full")
    args = parser.parse_args(argv)
    try:
        section = load_section(Path(args.rules))
        if args.stdin:
            paths = stdin_paths(sys.stdin.read())
        elif args.base:
            paths = diff_paths(Path(args.repo), args.base, args.head)
        else:
            parser.error("give --stdin or --base")
        emit(classify(section, paths, args.event_name, args.base_ref,
                      Path(args.repo)))
    except TypeError as exc:
        # A structurally wrong rules file (null, a non-list glob set): say so
        # and exit 1 with no verdict; the workflow then keeps both outputs false.
        common.log("cargo_skip: invalid rules shape: %s" % exc)
        return common.EXIT_FAIL
    except (OSError, ValueError, KeyError, RuntimeError,
            subprocess.SubprocessError) as exc:
        common.log("cargo_skip: %s" % exc)
        emit(verdict(FALSE, FALSE, REASON_ERROR))
    return common.EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
