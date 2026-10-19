#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Purge the top-level entries of a marked self-hosted runner TMPDIR (#7748).

CI jobs leave per-test scratch (sqlite databases with -wal/-shm sidecars,
ef-posture-audit-* trees, cargo test TMPDIR trees) under the runner's TMPDIR
(``_tmp``) and a failed, killed or cancelled job never reaches its own cleanup.
#7188 prunes ``<work-root>/_temp`` after a job; this closes the gap for the
TMPDIR itself. One job runs per runner at a time, so anything in the marked
TMPDIR at job start or job end is a leftover.

Opt-in: the node operator writes the marker file (``--marker``, default
``.ai-memory-ci-purgeable``) at the top level of a runner's TMPDIR once. A
TMPDIR without the marker is NEVER touched. The tool also refuses (one
``::notice::`` line, exit 0, never a red job) when TMPDIR is unset or empty,
does not exist, is a symlink, has fewer than 3 path components, is ``/``,
``/tmp``, ``/private/tmp``, ``/var/tmp`` or ``/var/folders`` (or anything under
them), or is the home directory or any ancestor of it. The check runs on the
given path and on its parent-resolved form, so ``/tmp`` is caught on macOS where
it is ``/private/tmp``.

When permitted it iterates ONLY the top-level entries (os.scandir + lstat),
skips the marker and entries younger than ``--older-than-minutes`` (default 0:
none are skipped), unlinks a symlink entry without following it, removes a
directory entry with shutil.rmtree (which unlinks a symlink met inside the tree
without entering it) and unlinks a file. The TMPDIR itself and the marker are
never removed. ``--apply`` removes; the default is a dry run that lists. The
summary line reports removed / failed / skipped counts and ``bytes`` (the sum of
the lstat sizes of the regular files freed; directories and symlinks count 0).

Exit codes: 0 always for a permitted, refused or partly failed run (cleanup must
never red a job; a failed removal is reported and counted), 2 for malformed
arguments. Python 3.9+, standard library only.
"""
import argparse
import os
import shutil
import stat
import sys
import time

DEFAULT_MARKER = ".ai-memory-ci-purgeable"
# Trees (the path itself or anything under it) that are never a runner TMPDIR.
FORBIDDEN_TREES = ("/tmp", "/private/tmp", "/var/tmp", "/private/var/tmp", "/var/folders", "/private/var/folders")
MIN_COMPONENTS = 3


def _under(path, tree):
    return path == tree or path.startswith(tree.rstrip(os.sep) + os.sep)


def _forms(path):
    """The absolute path as given and with its parent resolved (final component untouched)."""
    absolute = os.path.abspath(path)
    parent, leaf = os.path.split(absolute)
    resolved = os.path.join(os.path.realpath(parent), leaf) if leaf else absolute
    return [absolute] if resolved == absolute else [absolute, resolved]


def refusal_reason(path, home, forbidden=FORBIDDEN_TREES, marker=DEFAULT_MARKER):
    """Return why ``path`` must not be purged, or None when it may be.

    ``forbidden`` is a parameter so tests exercise the rule without touching real
    system directories; ``marker=None`` skips the filesystem checks (path rules only).
    """
    home_forms = _forms(home) if home else []
    for form in _forms(path):
        if len([p for p in form.split(os.sep) if p]) < MIN_COMPONENTS:
            return "fewer than %d path components: %s" % (MIN_COMPONENTS, form)
        for tree in forbidden:
            if _under(form, tree):
                return "forbidden system path: %s" % form
        for h in home_forms:
            if _under(h, form):
                return "home directory or an ancestor of it: %s" % form
    if marker is None:
        return None
    try:
        mode = os.lstat(path).st_mode
    except OSError:
        return "does not exist: %s" % path
    if stat.S_ISLNK(mode):
        return "symlinked tmpdir: %s" % path
    if not stat.S_ISDIR(mode):
        return "not a directory: %s" % path
    try:
        marker_mode = os.lstat(os.path.join(path, marker)).st_mode
    except OSError:
        return "no %s marker at the top level of %s" % (marker, path)
    if not stat.S_ISREG(marker_mode):
        return "marker %s is not a regular file" % marker
    return None


def _tree_bytes(path):
    total = 0
    for dirpath, _dirs, files in os.walk(path, followlinks=False):
        for name in files:
            try:
                st = os.lstat(os.path.join(dirpath, name))
            except OSError:
                continue
            if stat.S_ISREG(st.st_mode):
                total += st.st_size
    return total


def _entry_bytes(full, st):
    if stat.S_ISDIR(st.st_mode):
        return _tree_bytes(full)
    return st.st_size if stat.S_ISREG(st.st_mode) else 0


def purge(tmpdir, older_than_minutes, apply, marker, now=None):
    """Purge the top-level entries of ``tmpdir``; return the counts dict."""
    now = time.time() if now is None else now
    cutoff = now - older_than_minutes * 60
    counts = {"removed": 0, "failed": 0, "skipped": 0, "bytes": 0}
    with os.scandir(tmpdir) as it:
        names = sorted(entry.name for entry in it)
    for name in names:
        if name == marker:
            continue
        full = os.path.join(tmpdir, name)
        try:
            st = os.lstat(full)
        except OSError:
            counts["failed"] += 1
            continue
        if older_than_minutes > 0 and st.st_mtime > cutoff:
            counts["skipped"] += 1
            continue
        size = _entry_bytes(full, st)
        if not apply:
            print("would remove %s" % name)
            counts["removed"] += 1
            counts["bytes"] += size
            continue
        errors = []

        def report(_func, err_path, exc_info, errors=errors):
            errors.append((err_path, exc_info[1]))

        try:
            if stat.S_ISDIR(st.st_mode):
                shutil.rmtree(full, onerror=report)
            else:
                os.unlink(full)
        except OSError as exc:
            errors.append((full, exc))
        if errors or os.path.lexists(full):
            counts["failed"] += 1
            print("failed %s: %s" % (name, errors[0][1] if errors else "still present"), file=sys.stderr)
        else:
            counts["removed"] += 1
            counts["bytes"] += size
    return counts


def _non_negative(text):
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError("not an integer: %r" % text)
    if value < 0:
        raise argparse.ArgumentTypeError("must be >= 0: %r" % text)
    return value


def main(argv=None, environ=None):
    environ = os.environ if environ is None else environ
    parser = argparse.ArgumentParser(description="Purge a marked self-hosted runner TMPDIR (#7748).")
    parser.add_argument("--tmpdir", default=None, help="directory to purge (default: $TMPDIR)")
    parser.add_argument("--older-than-minutes", type=_non_negative, default=0)
    parser.add_argument("--apply", action="store_true", help="remove (default: dry run, list only)")
    parser.add_argument("--marker", default=DEFAULT_MARKER)
    args = parser.parse_args(argv)
    if os.sep in args.marker or args.marker in ("", ".", ".."):
        parser.error("--marker must be a plain file name")
    tmpdir = args.tmpdir if args.tmpdir is not None else environ.get("TMPDIR", "")
    if not tmpdir:
        print("::notice::clean_job_tmpdir: TMPDIR is unset or empty; nothing to purge")
        return 0
    home = os.path.expanduser("~")
    reason = refusal_reason(tmpdir, home, FORBIDDEN_TREES, args.marker)
    if reason:
        print("::notice::clean_job_tmpdir: refusing, %s" % reason)
        return 0
    counts = purge(tmpdir, args.older_than_minutes, args.apply, args.marker)
    print("clean_job_tmpdir: mode=%s removed=%d failed=%d skipped=%d bytes=%d dir=%s" % (
        "apply" if args.apply else "dry-run", counts["removed"], counts["failed"],
        counts["skipped"], counts["bytes"], tmpdir))
    return 0


if __name__ == "__main__":
    sys.exit(main())
