#!/usr/bin/env python3
"""A `git` stand-in that breaks ONLY `merge-tree`, for the #5065 self-test.

`scripts/check-commit-signing-posture.sh` exempts a merge from the commit
signing rule only when its recorded tree equals the clean
`git merge-tree --write-tree` of its two parents. That makes a git subcommand
load-bearing for a security gate on a runner (`ubuntu-latest`) where git is
not version-pinned, so the gate PROVES the subcommand is usable before it
walks a range and reports exit 2 (INOPERATIVE) when it is not. "I could not
compute the automerge" must never resolve to "the merge is exempt".

Those two refusals are branches, and a branch nothing exercises is a branch
nobody knows the state of. This shim is how the gate's own `--self-test`
takes them: it passes every invocation through to the real git except
`merge-tree`, which it breaks in one of two ways chosen by the name it is
invoked under (the self-test makes one symlink per mode, so the mode is in the
argv the gate is given and there is no environment variable to get wrong):

  * ``git-absent-merge-tree`` — exits 129 with a usage line on stderr, which
    is what a git too old to carry the subcommand does.
  * ``git-lying-merge-tree`` — exits 0 and prints the FIRST parent's tree oid:
    a well-formed 40-hex oid that really resolves as a tree, but not the merge
    of both sides. A capability probe that checked only the exit code and the
    output shape would accept it and would then compare a recorded tree
    against a value that means nothing — the shape-validated-never-resolved
    defect class. The gate's probe also asserts the merged CONTENT, so this
    shim must be refused.

Used only by the self-test. Never on a production path; nothing in CI invokes
it directly.
"""
import argparse
import os
import pathlib
import shutil
import subprocess
import sys

# git's own global options that consume the following argument. Anything else
# starting with `-` is a flag, and the first bare word after the globals is the
# subcommand.
VALUE_OPTS = frozenset((
    "-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path",
    "--config-env", "--super-prefix",
))

ABSENT_USAGE = (
    "usage: git merge-tree [--write-tree] [<options>] <branch1> <branch2>\n"
    "   or: git merge-tree [--trivial-merge] <base-tree> <branch1> <branch2>\n"
)


def split_argv(argv):
    """(global options, subcommand or None, remaining args)."""
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg in VALUE_OPTS:
            i += 2
            continue
        if arg.startswith("-"):
            i += 1
            continue
        return argv[:i], arg, argv[i + 1:]
    return argv, None, []


def real_git():
    found = shutil.which("git")
    if found is None:
        print("selftest-git-shim-merge-tree: no real git(1) on PATH",
              file=sys.stderr)
        raise SystemExit(127)
    return found


def mode_from_name(argv0):
    name = pathlib.Path(argv0).name
    if "absent" in name:
        return "absent"
    if "lying" in name:
        return "lying"
    print("selftest-git-shim-merge-tree: invoked as %r, which names no mode "
          "(expected a name containing 'absent' or 'lying')" % name,
          file=sys.stderr)
    raise SystemExit(2)


def main():
    # argparse is used for --help only: every other argument belongs to git and
    # is forwarded verbatim.
    if len(sys.argv) > 1 and sys.argv[1] in ("--shim-help",):
        argparse.ArgumentParser(description=__doc__).print_help()
        return 0

    argv = sys.argv[1:]
    globals_, subcommand, rest = split_argv(argv)

    if subcommand != "merge-tree":
        os.execv(real_git(), ["git"] + argv)

    mode = mode_from_name(sys.argv[0])
    if mode == "absent":
        sys.stderr.write(ABSENT_USAGE)
        return 129

    revs = [a for a in rest if not a.startswith("-")]
    if len(revs) < 2:
        sys.stderr.write(ABSENT_USAGE)
        return 129
    proc = subprocess.run(
        [real_git()] + globals_ + ["rev-parse", "%s^{tree}" % revs[0]],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr)
        return 1
    sys.stdout.write(proc.stdout.strip() + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
