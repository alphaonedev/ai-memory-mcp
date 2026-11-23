#!/usr/bin/env python3
"""Apply the one upstream Apache AGE fix of the certified build (#9965).

The certified AGE build is the pinned PG19 branch commit (AGE_SOURCE_COMMIT)
plus exactly one upstream commit, apache/age 06ce678d (#2580/#2581): it makes
is_age_extension_exists() return false outside a live transaction, so a
backend with age in shared_preload_libraries no longer opens pg_extension in
an aborted transaction and leaks a lock. Every builder (the Linux images, the
DO provisioner, cloud-init and the macOS f1 build steps in the docs) runs this
script between the source checkout and ``make``, and again with ``--verify``
after ``make install``.

Every pin is read from the SSOT (deploy/docker-1461/provision/lib.sh):
AGE_SOURCE_COMMIT, AGE_PATCH_UPSTREAM_COMMIT, AGE_PATCH_FILE (a basename under
``patches/`` beside the SSOT), AGE_PATCH_SHA256 and AGE_PATCHED_FILE_SHA256.
The patch file holds only the diff body of the upstream commit (written by
deploy/docker-1461/provision/gen_age_patch.py); its provenance is the pin
AGE_PATCH_UPSTREAM_COMMIT and AGE_PATCH_SHA256 covers its stored bytes.

Steps, each fail closed with its own exit code, in this order:
  1. ``--src`` is a directory (exit 2) and is the toplevel of its git
     checkout (exit 7);
  2. the SSOT is readable and every pin is set once in its shape (exit 2);
  3. the checkout HEAD is AGE_SOURCE_COMMIT (exit 3);
  4. the patch is read ONCE through a descriptor opened without following a
     symlink; a symlinked patch or patch directory, a file that is not
     regular, a patch directory that resolves outside the SSOT directory, a
     sha256 other than AGE_PATCH_SHA256, a first line other than
     ``diff --git a/<file> b/<file>`` or a diff of any other file is refused
     (exit 4);
  5. ``git apply --check`` of exactly those bytes (on stdin) applies with no
     offset, fuzz or reject, then ``git apply`` applies the same bytes (exit 5);
  6. the patched file is not a symlink, the guard sits at the head of
     is_age_extension_exists() and the file's sha256 matches the pin (exit 6).
``--verify`` runs steps 1 to 3 and step 6 on an already patched tree.
``--print-pin KEY`` prints one pin after step 2 and touches no source tree.
On success one provenance line is printed:
  age-patch: applied <file> (upstream apache/age <sha>, sha256 <x>) onto <commit>; patched ag_catalog.c sha256 <y>
"""
import argparse
import hashlib
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

EXIT_OK = 0
EXIT_BAD_INPUT = 2
EXIT_SOURCE_MISMATCH = 3
EXIT_PATCH_MISMATCH = 4
EXIT_APPLY_FAILED = 5
EXIT_GUARD_MISSING = 6
EXIT_SRC_NOT_TOPLEVEL = 7

PATCHED_FILE = "src/backend/catalog/ag_catalog.c"
PATCH_DIR = "patches"
PATCH_FIRST_LINE = f"diff --git a/{PATCHED_FILE} b/{PATCHED_FILE}"
DIFF_HEADER_RE = re.compile(rb"^diff --git (.*)$", re.MULTILINE)
GIT_TIMEOUT_SECONDS = 120
# The patch is a one-function fix; anything larger than this is not it.
MAX_PATCH_BYTES = 1 << 20
SHA1_RE = r"[0-9a-f]{40}"
SHA256_RE = r"[0-9a-f]{64}"
PIN_SHAPES = {
    "AGE_SOURCE_COMMIT": SHA1_RE,
    "AGE_PATCH_UPSTREAM_COMMIT": SHA1_RE,
    "AGE_PATCH_FILE": r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.patch",
    "AGE_PATCH_SHA256": SHA256_RE,
    "AGE_PATCHED_FILE_SHA256": SHA256_RE,
}
# The guard the upstream commit adds, as the first statements after the
# static declaration of is_age_extension_exists().
GUARD_RE = re.compile(
    r"\nis_age_extension_exists\(void\)\n\{\n    static bool callback_registered = false;\n\n"
    r"(?:    /\*(?:[^*]|\*(?!/))*\*/\n)?"
    r"    if \(!IsTransactionState\(\)\)\n        return false;\n\n"
    r"    if \(extension_cache_is_valid\)\n"
)
# git apply --verbose reports a moved hunk ("Hunk #1 succeeded at 80 (offset 5 lines)")
# or a fuzzy one ("with fuzz"); the certified build applies at zero offset only.
INEXACT_APPLY = re.compile(r"(?i)offset|fuzz|reject|warning")


class PatchError(Exception):
    def __init__(self, message, code):
        super().__init__(message)
        self.code = code


def read_pins(ssot):
    try:
        text = ssot.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise PatchError(f"SSOT {ssot} is unreadable ({type(exc).__name__})", EXIT_BAD_INPUT)
    pins = {}
    for key, shape in PIN_SHAPES.items():
        found = re.findall(rf'^{key}="\$\{{DOCKER_1461_{key}:-([^}}"]*)\}}"(?:[ \t]+#[^\n]*)?$', text, re.MULTILINE)
        if len(found) != 1 or re.fullmatch(shape, found[0]) is None:
            raise PatchError(f"pin {key} is not set exactly once in the shape {shape} in {ssot}", EXIT_BAD_INPUT)
        pins[key] = found[0]
    return pins


def git(src, *args, stdin=None):
    """Run git in src; stdin is bytes or None. Output is decoded with replacement."""
    try:
        proc = subprocess.run(["git", "-C", str(src), *args], input=stdin if stdin is not None else b"",
                              capture_output=True, check=False, timeout=GIT_TIMEOUT_SECONDS)
    except (OSError, subprocess.SubprocessError) as exc:
        raise PatchError(f"git {args[0]} could not run ({type(exc).__name__})", EXIT_APPLY_FAILED)
    return subprocess.CompletedProcess(proc.args, proc.returncode, proc.stdout.decode("utf-8", "replace"),
                                       proc.stderr.decode("utf-8", "replace"))


def require_toplevel(src):
    if not src.is_dir():
        raise PatchError(f"source directory {src} is not a directory", EXIT_BAD_INPUT)
    proc = git(src, "rev-parse", "--show-toplevel")
    top = proc.stdout.strip()
    if proc.returncode != 0 or not top or Path(top).resolve() != src.resolve():
        raise PatchError(f"source directory {src} is not the toplevel of a git checkout", EXIT_SRC_NOT_TOPLEVEL)


def require_head(src, pins):
    proc = git(src, "rev-parse", "HEAD")
    head = proc.stdout.strip()
    if proc.returncode != 0 or head != pins["AGE_SOURCE_COMMIT"]:
        shown = head if re.fullmatch(SHA1_RE, head) else "no commit"
        raise PatchError(f"AGE checkout is at {shown}, not AGE_SOURCE_COMMIT {pins['AGE_SOURCE_COMMIT']}",
                         EXIT_SOURCE_MISMATCH)


def read_patch_once(ssot, name):
    """The patch bytes, read through one descriptor that never follows a symlink."""
    patch_dir = ssot.parent / PATCH_DIR
    if patch_dir.is_symlink():
        raise PatchError(f"patch directory {patch_dir} is a symlink", EXIT_PATCH_MISMATCH)
    if patch_dir.resolve().parent != ssot.parent.resolve():
        raise PatchError(f"patch directory {patch_dir} resolves outside {ssot.parent}", EXIT_PATCH_MISMATCH)
    path = patch_dir / name
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0))
    except OSError as exc:
        if path.is_symlink():
            raise PatchError(f"patch {name} is a symlink", EXIT_PATCH_MISMATCH)
        raise PatchError(f"patch {name} is unreadable ({type(exc).__name__})", EXIT_PATCH_MISMATCH)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise PatchError(f"patch {name} is not a regular file", EXIT_PATCH_MISMATCH)
        chunks, size = [], 0
        while chunk := os.read(fd, 65536):
            size += len(chunk)
            if size > MAX_PATCH_BYTES:
                raise PatchError(f"patch {name} is larger than {MAX_PATCH_BYTES} bytes", EXIT_PATCH_MISMATCH)
            chunks.append(chunk)
    except OSError as exc:
        raise PatchError(f"patch {name} is unreadable ({type(exc).__name__})", EXIT_PATCH_MISMATCH)
    finally:
        os.close(fd)
    return b"".join(chunks)


def require_patch(data, name, pins):
    digest = hashlib.sha256(data).hexdigest()
    if digest != pins["AGE_PATCH_SHA256"]:
        raise PatchError(f"patch {name} sha256 {digest} is not AGE_PATCH_SHA256 {pins['AGE_PATCH_SHA256']}",
                         EXIT_PATCH_MISMATCH)
    first = data.split(b"\n", 1)[0].decode("ascii", "replace")
    if first != PATCH_FIRST_LINE:
        raise PatchError(f"patch {name} does not open with {PATCH_FIRST_LINE}", EXIT_PATCH_MISMATCH)
    headers = DIFF_HEADER_RE.findall(data)
    if headers != [PATCH_FIRST_LINE[len("diff --git "):].encode()]:
        raise PatchError(f"patch {name} changes a file other than {PATCHED_FILE}", EXIT_PATCH_MISMATCH)
    return digest


def require_guard(src, pins):
    target = src / PATCHED_FILE
    try:
        fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as exc:
        if target.is_symlink():
            raise PatchError(f"{PATCHED_FILE} is a symlink", EXIT_GUARD_MISSING)
        raise PatchError(f"{PATCHED_FILE} is unreadable ({type(exc).__name__})", EXIT_GUARD_MISSING)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise PatchError(f"{PATCHED_FILE} is not a regular file", EXIT_GUARD_MISSING)
        with os.fdopen(os.dup(fd), "rb") as fh:
            data = fh.read()
    finally:
        os.close(fd)
    if GUARD_RE.search(data.decode("utf-8", "replace")) is None:
        raise PatchError(f"{PATCHED_FILE} lacks the IsTransactionState() guard of upstream "
                         f"{pins['AGE_PATCH_UPSTREAM_COMMIT']}", EXIT_GUARD_MISSING)
    digest = hashlib.sha256(data).hexdigest()
    if digest != pins["AGE_PATCHED_FILE_SHA256"]:
        raise PatchError(f"{PATCHED_FILE} sha256 {digest} is not AGE_PATCHED_FILE_SHA256 "
                         f"{pins['AGE_PATCHED_FILE_SHA256']}", EXIT_GUARD_MISSING)
    return digest


def apply(src, ssot, verify):
    require_toplevel(src)
    pins = read_pins(ssot)
    require_head(src, pins)
    name = pins["AGE_PATCH_FILE"]
    data = read_patch_once(ssot, name)
    patch_digest = require_patch(data, name, pins)
    if not verify:
        check = git(src, "apply", "--check", "--verbose", "-", stdin=data)
        if check.returncode != 0 or INEXACT_APPLY.search(check.stderr + check.stdout):
            raise PatchError(f"patch {name} does not apply exactly onto {pins['AGE_SOURCE_COMMIT']} "
                             f"(exit {check.returncode})", EXIT_APPLY_FAILED)
        done = git(src, "apply", "-", stdin=data)
        if done.returncode != 0:
            raise PatchError(f"git apply {name} failed (exit {done.returncode})", EXIT_APPLY_FAILED)
    file_digest = require_guard(src, pins)
    verb = "verified" if verify else "applied"
    return (f"age-patch: {verb} {name} (upstream apache/age {pins['AGE_PATCH_UPSTREAM_COMMIT']}, "
            f"sha256 {patch_digest}) onto {pins['AGE_SOURCE_COMMIT']}; patched ag_catalog.c sha256 {file_digest}")


def main(argv=None):
    p = argparse.ArgumentParser(description="Apply and verify the certified Apache AGE fix (#9965).")
    p.add_argument("--ssot", type=Path, required=True, help="path of deploy/docker-1461/provision/lib.sh")
    p.add_argument("--src", type=Path, help="the toplevel of the AGE git checkout at AGE_SOURCE_COMMIT")
    p.add_argument("--verify", action="store_true", help="check an already patched tree; apply nothing")
    p.add_argument("--print-pin", choices=sorted(PIN_SHAPES), help="print one validated pin and exit")
    args = p.parse_args(argv)
    if args.print_pin is None and args.src is None:
        p.error("--src is required unless --print-pin is given")
    try:
        if args.print_pin is not None:
            print(read_pins(args.ssot)[args.print_pin])
        else:
            print(apply(args.src, args.ssot, args.verify))
    except PatchError as exc:
        print(f"apply_age_patch: {exc}", file=sys.stderr)
        return exc.code
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
