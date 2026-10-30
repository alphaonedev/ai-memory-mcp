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
"""
import argparse
import subprocess
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Optional

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
             base_ref: str = "") -> Dict[str, str]:
    """Return the three output values for the changed `paths`."""
    version = "cargo_skip-rules-v%s" % section["version"]
    forced = full_ci_reason(section, event_name, base_ref)
    if forced:
        return verdict(FALSE, FALSE, "%s %s" % (forced, version))
    if not paths:
        return verdict(FALSE, FALSE, "%s %s" % (REASON_EMPTY, version))
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
        cwd=str(repo), capture_output=True, timeout=GIT_TIMEOUT_S)
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
    """Classify the diff; exit 0 with a fail-closed verdict on error, exit 1 on a wrong rules shape."""
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
        emit(classify(section, paths, args.event_name, args.base_ref))
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
