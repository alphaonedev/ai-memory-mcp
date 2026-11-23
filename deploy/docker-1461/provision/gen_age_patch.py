#!/usr/bin/env python3
"""Write the certified Apache AGE patch file from its upstream commit (#9951, #9983).

The patch beside the SSOT (deploy/docker-1461/provision/patches/<AGE_PATCH_FILE>)
holds only a diff body: no mail header, no commit message and no signature.
Its provenance is the pin AGE_PATCH_UPSTREAM_COMMIT in lib.sh, and
AGE_PATCH_SHA256 covers the stored bytes. This script makes the file
reproducible: given an apache/age clone that holds both the upstream commit
(on master) and AGE_SOURCE_COMMIT (the PG19 branch), it takes

    git diff --full-index <upstream>^ <upstream>

applies it to the tree of AGE_SOURCE_COMMIT in a private index (exact context,
an offset allowed, no fuzz) and writes the diff from AGE_SOURCE_COMMIT to the
result, all under a fixed configuration (no system or global git config, no
external diff, no textconv, no renames, no colour, the default a/ b/
prefixes). It refuses a commit that is not a single-parent commit, a change
that does not apply onto AGE_SOURCE_COMMIT, and a diff of any file other than
src/backend/catalog/ag_catalog.c.

    gen_age_patch.py --ssot lib.sh --age <clone>            write the file, print its sha256
    gen_age_patch.py --ssot lib.sh --age <clone> --check    exit 1 when the stored file differs

Exit codes: 0 written (or identical under --check), 1 the stored file differs
(--check), 2 bad input (SSOT, pin, clone), 3 git failed or the commit is not a
single-parent commit, 4 the change does not apply onto AGE_SOURCE_COMMIT or is
not a diff of the one patched file.
"""
import argparse
import hashlib
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import apply_age_patch as applier  # noqa: E402

EXIT_OK = 0
EXIT_DIFFERS = 1
EXIT_BAD_INPUT = 2
EXIT_GIT_FAILED = 3
EXIT_NOT_THE_FIX = 4
GIT_TIMEOUT_SECONDS = 120
# A fixed git environment so the bytes never depend on the caller's config.
GIT_ENV_FIXED = {"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull, "LC_ALL": "C"}
GIT_DIFF_ARGS = ("-c", "diff.noprefix=false", "-c", "diff.mnemonicPrefix=false", "-c", "core.quotePath=true",
                 "diff", "--full-index", "--no-color", "--no-ext-diff", "--no-textconv", "--no-renames")


class GenError(Exception):
    def __init__(self, message, code):
        super().__init__(message)
        self.code = code


def run_git(clone, *args, stdin=b"", index=None, failure=None):
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(GIT_ENV_FIXED)
    if index is not None:
        env["GIT_INDEX_FILE"] = str(index)
    try:
        proc = subprocess.run(["git", "-C", str(clone), *args], capture_output=True, check=False,
                              timeout=GIT_TIMEOUT_SECONDS, env=env, input=stdin)
    except (OSError, subprocess.SubprocessError) as exc:
        raise GenError(f"git {args[0]} could not run ({type(exc).__name__})", EXIT_GIT_FAILED)
    if proc.returncode != 0:
        if failure is not None:
            raise failure
        raise GenError(f"git {' '.join(a for a in args if not a.startswith('-c'))[:80]} failed "
                       f"(exit {proc.returncode})", EXIT_GIT_FAILED)
    return proc.stdout


def require_one_file(body, what):
    headers = applier.DIFF_HEADER_RE.findall(body)
    if not body.startswith(applier.PATCH_FIRST_LINE.encode() + b"\n") or len(headers) != 1:
        raise GenError(f"{what} changes a file other than {applier.PATCHED_FILE}", EXIT_NOT_THE_FIX)


def diff_body(clone, commit, source):
    """The upstream change of `commit`, carried onto `source` (the pinned PG19 branch commit).

    The upstream commit sits on apache/age master; the certified tree is the
    PG19 branch commit AGE_SOURCE_COMMIT. Its diff is applied to the tree of
    `source` in a private index (git apply --cached: exact context, an offset
    allowed, no fuzz), and the body is the diff from `source` to that tree, so
    the applier applies it onto AGE_SOURCE_COMMIT at zero offset.
    """
    if not clone.is_dir():
        raise GenError(f"AGE clone {clone} is not a directory", EXIT_BAD_INPUT)
    parents = run_git(clone, "rev-list", "--parents", "-n", "1", commit).decode("ascii", "replace").split()
    if len(parents) != 2 or parents[0] != commit:
        raise GenError(f"upstream commit {commit} is not a single-parent commit in {clone}", EXIT_GIT_FAILED)
    upstream = run_git(clone, *GIT_DIFF_ARGS, f"{commit}^", commit)
    require_one_file(upstream, f"upstream commit {commit}")
    git_dir = Path(run_git(clone, "rev-parse", "--absolute-git-dir").decode("utf-8", "replace").strip())
    index = git_dir / f"gen-age-patch-{os.getpid()}.index"
    try:
        run_git(clone, "read-tree", f"{source}^{{tree}}", index=index)
        run_git(clone, "apply", "--cached", "-", stdin=upstream, index=index,
                failure=GenError(f"upstream commit {commit} does not apply onto AGE_SOURCE_COMMIT {source}",
                                 EXIT_NOT_THE_FIX))
        tree = run_git(clone, "write-tree", index=index).decode("ascii", "replace").strip()
    finally:
        index.unlink(missing_ok=True)
    body = run_git(clone, *GIT_DIFF_ARGS, source, tree)
    require_one_file(body, f"upstream commit {commit} carried onto {source}")
    return body


def generate(ssot, clone, check):
    try:
        pins = applier.read_pins(ssot)
    except applier.PatchError as exc:
        raise GenError(str(exc), EXIT_BAD_INPUT)
    body = diff_body(clone, pins["AGE_PATCH_UPSTREAM_COMMIT"], pins["AGE_SOURCE_COMMIT"])
    out = ssot.parent / applier.PATCH_DIR / pins["AGE_PATCH_FILE"]
    digest = hashlib.sha256(body).hexdigest()
    if check:
        try:
            stored = out.read_bytes()
        except OSError as exc:
            raise GenError(f"patch {out.name} is unreadable ({type(exc).__name__})", EXIT_BAD_INPUT)
        if stored != body:
            raise GenError(f"patch {out.name} sha256 {hashlib.sha256(stored).hexdigest()} is not the "
                           f"diff body of {pins['AGE_PATCH_UPSTREAM_COMMIT']} (sha256 {digest})", EXIT_DIFFERS)
        return f"gen-age-patch: {out.name} matches upstream {pins['AGE_PATCH_UPSTREAM_COMMIT']} (sha256 {digest})"
    if out.is_symlink():
        raise GenError(f"patch {out.name} is a symlink", EXIT_BAD_INPUT)
    out.write_bytes(body)
    return f"gen-age-patch: wrote {out.name} from upstream {pins['AGE_PATCH_UPSTREAM_COMMIT']} (sha256 {digest})"


def main(argv=None):
    p = argparse.ArgumentParser(description="Write the certified AGE patch file from its upstream commit.")
    p.add_argument("--ssot", type=Path, required=True, help="path of deploy/docker-1461/provision/lib.sh")
    p.add_argument("--age", type=Path, required=True, help="an apache/age clone that holds the upstream commit")
    p.add_argument("--check", action="store_true", help="compare with the stored file; write nothing")
    args = p.parse_args(argv)
    try:
        print(generate(args.ssot, args.age, args.check))
    except GenError as exc:
        print(f"gen_age_patch: {exc}", file=sys.stderr)
        return exc.code
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
