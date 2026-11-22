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

Steps, each fail closed with its own exit code:
  1. the checkout HEAD is AGE_SOURCE_COMMIT (exit 3);
  2. the patch file's sha256 and its ``From <sha>`` header match the pins (exit 4);
  3. ``git apply --check`` applies with no offset, fuzz or reject (exit 5);
  4. after applying, the guard sits at the head of is_age_extension_exists()
     and the patched file's sha256 matches the pin (exit 6).
``--verify`` runs only step 1 (HEAD) and step 4 on an already patched tree.
Exit 2 is bad input (SSOT unreadable, a pin missing or malformed, a source
directory that is not a directory). On success one provenance line is printed:
  age-patch: applied <file> (upstream apache/age <sha>, sha256 <x>) onto <commit>; patched ag_catalog.c sha256 <y>
"""
import argparse
import hashlib
import re
import subprocess
import sys
from pathlib import Path

EXIT_OK = 0
EXIT_BAD_INPUT = 2
EXIT_SOURCE_MISMATCH = 3
EXIT_PATCH_MISMATCH = 4
EXIT_APPLY_FAILED = 5
EXIT_GUARD_MISSING = 6

PATCHED_FILE = "src/backend/catalog/ag_catalog.c"
PATCH_DIR = "patches"
GIT_TIMEOUT_SECONDS = 120
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


def git(src, *args):
    try:
        return subprocess.run(["git", "-C", str(src), *args], capture_output=True, text=True,
                              errors="replace", check=False, timeout=GIT_TIMEOUT_SECONDS)
    except (OSError, subprocess.SubprocessError) as exc:
        raise PatchError(f"git {args[0]} could not run ({type(exc).__name__})", EXIT_APPLY_FAILED)


def require_head(src, pins):
    proc = git(src, "rev-parse", "HEAD")
    head = proc.stdout.strip()
    if proc.returncode != 0 or head != pins["AGE_SOURCE_COMMIT"]:
        shown = head if re.fullmatch(SHA1_RE, head) else "no commit"
        raise PatchError(f"AGE checkout is at {shown}, not AGE_SOURCE_COMMIT {pins['AGE_SOURCE_COMMIT']}",
                         EXIT_SOURCE_MISMATCH)


def require_patch(patch, pins):
    try:
        data = patch.read_bytes()
    except OSError as exc:
        raise PatchError(f"patch {patch.name} is unreadable ({type(exc).__name__})", EXIT_PATCH_MISMATCH)
    digest = hashlib.sha256(data).hexdigest()
    if digest != pins["AGE_PATCH_SHA256"]:
        raise PatchError(f"patch {patch.name} sha256 {digest} is not AGE_PATCH_SHA256 {pins['AGE_PATCH_SHA256']}",
                         EXIT_PATCH_MISMATCH)
    first = data.split(b"\n", 1)[0].decode("ascii", "replace")
    if first != f"From {pins['AGE_PATCH_UPSTREAM_COMMIT']} Mon Sep 17 00:00:00 2001":
        raise PatchError(f"patch {patch.name} does not open with upstream commit "
                         f"{pins['AGE_PATCH_UPSTREAM_COMMIT']}", EXIT_PATCH_MISMATCH)
    return digest


def require_guard(src, pins):
    target = src / PATCHED_FILE
    try:
        data = target.read_bytes()
    except OSError as exc:
        raise PatchError(f"{PATCHED_FILE} is unreadable ({type(exc).__name__})", EXIT_GUARD_MISSING)
    if GUARD_RE.search(data.decode("utf-8", "replace")) is None:
        raise PatchError(f"{PATCHED_FILE} lacks the IsTransactionState() guard of upstream "
                         f"{pins['AGE_PATCH_UPSTREAM_COMMIT']}", EXIT_GUARD_MISSING)
    digest = hashlib.sha256(data).hexdigest()
    if digest != pins["AGE_PATCHED_FILE_SHA256"]:
        raise PatchError(f"{PATCHED_FILE} sha256 {digest} is not AGE_PATCHED_FILE_SHA256 "
                         f"{pins['AGE_PATCHED_FILE_SHA256']}", EXIT_GUARD_MISSING)
    return digest


def apply(src, ssot, verify):
    pins = read_pins(ssot)
    if not src.is_dir():
        raise PatchError(f"source directory {src} is not a directory", EXIT_BAD_INPUT)
    require_head(src, pins)
    patch = ssot.parent / PATCH_DIR / pins["AGE_PATCH_FILE"]
    patch_digest = require_patch(patch, pins)
    if not verify:
        check = git(src, "apply", "--check", "--verbose", str(patch))
        if check.returncode != 0 or INEXACT_APPLY.search(check.stderr + check.stdout):
            raise PatchError(f"patch {patch.name} does not apply exactly onto {pins['AGE_SOURCE_COMMIT']} "
                             f"(exit {check.returncode})", EXIT_APPLY_FAILED)
        done = git(src, "apply", str(patch))
        if done.returncode != 0:
            raise PatchError(f"git apply {patch.name} failed (exit {done.returncode})", EXIT_APPLY_FAILED)
    file_digest = require_guard(src, pins)
    verb = "verified" if verify else "applied"
    return (f"age-patch: {verb} {patch.name} (upstream apache/age {pins['AGE_PATCH_UPSTREAM_COMMIT']}, "
            f"sha256 {patch_digest}) onto {pins['AGE_SOURCE_COMMIT']}; patched ag_catalog.c sha256 {file_digest}")


def main(argv=None):
    p = argparse.ArgumentParser(description="Apply and verify the certified Apache AGE fix (#9965).")
    p.add_argument("--ssot", type=Path, required=True, help="path of deploy/docker-1461/provision/lib.sh")
    p.add_argument("--src", type=Path, required=True, help="the AGE git checkout at AGE_SOURCE_COMMIT")
    p.add_argument("--verify", action="store_true", help="check an already patched tree; apply nothing")
    args = p.parse_args(argv)
    try:
        print(apply(args.src, args.ssot, args.verify))
    except PatchError as exc:
        print(f"apply_age_patch: {exc}", file=sys.stderr)
        return exc.code
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
