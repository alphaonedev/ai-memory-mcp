#!/usr/bin/env python3
"""A `git` stand-in that breaks ONE subcommand, for the signing gate's self-test.

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
`merge-tree`, which it breaks in one of six ways chosen by the name it is
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
  * ``git-twoline-merge-tree`` — exits 0 and prints the real merged tree oid
    followed by a second line, so only the exactly-one-line assertion can
    refuse it (#5277).
  * ``git-nonhex-merge-tree`` — exits 0 and prints one line that is not a
    40-hex oid, so only the 40-hex assertion can refuse it.
  * ``git-ghost-merge-tree`` — exits 0 and prints one well-formed 40-hex oid
    that names no object, so only the resolves-as-a-tree assertion can refuse
    it. (A commit oid would not reach that assertion's refusal: `<commit>^{tree}`
    peels to the commit's tree, and the content assertion catches it instead.)
  * ``git-terse-merge-tree`` — runs the real merge-tree and keeps its exit
    status, but prints only the FIRST line. On a conflict that is a valid
    tree oid at rc=1, so only the gate's rc check can refuse it (#5278).

The same shim also breaks ONLY `log`, for the commit WALK (#5272, #5138). The
walk is the gate's only source of the commits it judges, so a walk that dies
partway, comes up short, tears its last record or carries a malformed field
must be INOPERATIVE (exit 2), never a PASS over the commits it happened to
read. Six more names select those modes; each runs the real `git log` first
and then damages its output:

  * ``git-truncated-log`` — emits only the FIRST record, then exits 128 with a
    ``fatal:`` line, the way a walk that hits a missing object does.
  * ``git-short-log`` — emits every record but the last and exits 0: a walk
    whose exit status is clean but whose output is short, which only a
    record-count cross-check can see.
  * ``git-torn-log`` — emits every record but the last, then the first three
    fields of the last one, and exits 0.
  * ``git-malformed-log`` — replaces the FIRST record's signature-status field
    (`%G?`) with a value git never emits, and exits 0.
  * ``git-trailing-log`` — emits every record intact, then a fragment with no
    terminating NUL, and exits 0: a stream that ends inside a record's FIRST
    field, which only an end-of-stream check can see (every whole record is
    present, so the record count still matches).
  * ``git-orphan-log`` — emits every record intact, then SIGKILLs its PARENT
    (the gate's walk producer), so the producer dies before it can record the
    walk's exit status: the records are complete and correct, and only the
    missing status says the walk was never confirmed.

Records are NUL-delimited fields when the walk passes ``-z`` (the field count
is read from the ``--format`` argument), and ``|``-delimited lines otherwise,
so the shim damages either record format the same way.

Used only by the self-test. Never on a production path; nothing in CI invokes
it directly.
"""
import argparse
import os
import pathlib
import shutil
import signal
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


LOG_MODES = ("truncated-log", "short-log", "torn-log", "malformed-log", "trailing-log", "orphan-log")
MERGE_TREE_MODES = ("absent", "lying", "twoline", "nonhex", "ghost", "terse")
GHOST_OID = "0123456789abcdef0123456789abcdef01234567"


def mode_from_name(argv0):
    name = pathlib.Path(argv0).name
    for mode in MERGE_TREE_MODES + LOG_MODES:
        if mode in name:
            return mode
    print("selftest-git-shim-merge-tree: invoked as %r, which names no mode "
          "(expected a name containing one of %s)"
          % (name, ", ".join(MERGE_TREE_MODES + LOG_MODES)), file=sys.stderr)
    raise SystemExit(2)


def split_records(out, rest):
    """(records as lists of fields, nul_mode, fields per record)."""
    if "-z" in rest:
        fmt = ""
        for arg in rest:
            if arg.startswith("--format="):
                fmt = arg.split("=", 1)[1]
        width = fmt.count("%x00") + 1
        toks = out.split(b"\0")
        if toks and toks[-1] == b"":
            toks.pop()
        if len(toks) % width != 0:
            print("selftest-git-shim-merge-tree: real git log emitted %d fields, "
                  "not a multiple of %d" % (len(toks), width), file=sys.stderr)
            raise SystemExit(2)
        recs = [toks[i:i + width] for i in range(0, len(toks), width)]
        return recs, True, width
    lines = out.split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()
    return [line.split(b"|") for line in lines], False, 0


def encode(recs, nul_mode):
    if nul_mode:
        return b"".join(field + b"\0" for rec in recs for field in rec)
    return b"".join(b"|".join(rec) + b"\n" for rec in recs)


def broken_log(mode, argv, rest):
    """Run the real `git log`, then damage its output as MODE says."""
    proc = subprocess.run([real_git()] + argv, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, check=False)
    if proc.returncode != 0:
        sys.stderr.buffer.write(proc.stderr)
        return proc.returncode
    recs, nul_mode, _width = split_records(proc.stdout, rest)
    if len(recs) < 2:
        print("selftest-git-shim-merge-tree: mode %s needs a range of at least "
              "two commits, got %d" % (mode, len(recs)), file=sys.stderr)
        return 2
    out = sys.stdout.buffer
    if mode == "truncated-log":
        out.write(encode(recs[:1], nul_mode))
        out.flush()
        sys.stderr.write("fatal: bad object (selftest shim: walk truncated)\n")
        return 128
    if mode == "short-log":
        out.write(encode(recs[:-1], nul_mode))
        return 0
    if mode == "torn-log":
        partial = recs[-1][:3]
        out.write(encode(recs[:-1], nul_mode))
        if nul_mode:
            out.write(b"".join(field + b"\0" for field in partial))
        else:
            out.write(b"|".join(partial))
        return 0
    if mode == "trailing-log":
        out.write(encode(recs, nul_mode))
        out.write(recs[-1][0][:12])
        return 0
    if mode == "orphan-log":
        out.write(encode(recs, nul_mode))
        out.flush()
        os.kill(os.getppid(), signal.SIGKILL)
        return 0
    # malformed-log
    recs[0][3] = b"Z"
    out.write(encode(recs, nul_mode))
    return 0


def main():
    # argparse is used for --help only: every other argument belongs to git and
    # is forwarded verbatim.
    if len(sys.argv) > 1 and sys.argv[1] in ("--shim-help",):
        argparse.ArgumentParser(description=__doc__).print_help()
        return 0

    argv = sys.argv[1:]
    globals_, subcommand, rest = split_argv(argv)

    mode = mode_from_name(sys.argv[0])
    if mode in LOG_MODES:
        if subcommand != "log":
            os.execv(real_git(), ["git"] + argv)
        return broken_log(mode, argv, rest)

    if subcommand != "merge-tree":
        os.execv(real_git(), ["git"] + argv)

    if mode == "absent":
        sys.stderr.write(ABSENT_USAGE)
        return 129

    if mode == "nonhex":
        sys.stdout.write("merge-tree: not-a-tree-oid\n")
        return 0
    if mode == "ghost":
        sys.stdout.write(GHOST_OID + "\n")
        return 0
    if mode == "terse":
        proc = subprocess.run([real_git()] + argv, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True, check=False)
        sys.stdout.write(proc.stdout.split("\n", 1)[0] + "\n")
        return proc.returncode
    if mode == "twoline":
        proc = subprocess.run([real_git()] + argv, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True, check=False)
        if proc.returncode != 0:
            sys.stderr.write(proc.stderr)
            return proc.returncode
        sys.stdout.write(proc.stdout.strip() + "\nsecond line\n")
        return 0

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
