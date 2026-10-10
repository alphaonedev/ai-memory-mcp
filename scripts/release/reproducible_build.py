#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""reproducible_build.py — two-build byte-identity proof of a release binary (#3613).

#3546's reproducible-build provision ("so the soaked binary is the tagged
binary") needs evidence, not a claim: build the release binary TWICE from the
same verified commit, in two separate workspaces, with the deterministic inputs
the release job uses, and require the two SHA-256 digests to be equal.

Deterministic inputs (the same ones release.yml's build step exports, so a
proof here is about the configuration the shipped binary is built with):

  * ``--locked`` against the committed Cargo.lock and the pinned toolchain
    (whatever ``cargo`` resolves to in the caller's environment);
  * ``SOURCE_DATE_EPOCH`` = the committer timestamp of the workspace's HEAD
    (``git log -1 --format=%ct``), unless ``--epoch`` overrides it;
  * ``RUSTFLAGS`` remapping each workspace to ``/src`` and CARGO_HOME to
    ``/cargo`` (``--remap-path-prefix``), so a path that leaks into the binary
    leaks identically from both workspaces.

Workspace B is a detached ``git worktree`` of workspace A's HEAD. An existing
directory is accepted only when it is a clean checkout of exactly A's HEAD
(#6291). No build cache is shared or restored: each build runs with an
allowlisted environment (BUILD_ENV_ALLOWLIST), its own CARGO_TARGET_DIR and no
compiler wrapper; a caller that sets RUSTC_WRAPPER / RUSTC_WORKSPACE_WRAPPER is
refused. The point is two independent builds.

On a mismatch the script prints both digests, both sizes, the number of
differing bytes and the first differing offset, the ELF section table of each
binary (``readelf -S``, when present) and a ``diffoscope`` report (when
installed), then exits 1. A build that fails, a binary that is missing, or a
git / worktree error exits 2. Only an exact digest match exits 0.

#6282 / #6283: ``--pack OUT --epoch E NAME...`` writes a deterministic
``.tar.gz`` of NAMEs (relative to ``--pack-root``, default the current
directory): members sorted, every mtime = E, owner 0/0 with empty names, modes
normalised to 0644 / 0755, no gzip timestamp or file name. The release job
packs every shipped tarball with it. The two-build proof packs each build's
binary the same way and compares the tarballs; with ``--nfpm`` it also builds
the deb and rpm of each workspace (``nfpm.yaml``, ``SOURCE_DATE_EPOCH``) and
compares them. Any difference is a mismatch (exit 1).

#6907: the release job's package units read the asserted binary through this
script, never through a PATH tool. ``--sha256 FILE`` prints the SHA-256 of one
read of a regular file (no symlink). ``--pack-binary`` reads SRC once, refuses
it unless its SHA-256 is ``--expect-sha256`` (the digest the strict assert
recorded), and writes the tarball (``--pack``) and ``--copy-to`` from those same
bytes. ``--verify-payload`` opens each deb (ar + data.tar) and rpm (lead,
headers, gzip / xz / bzip2 newc cpio; zstd is refused) and requires exactly one
regular file, ``usr/bin/ai-memory``, single-linked, mode 0755, with the
expected SHA-256.

``--self-test`` drives the comparison with a stub ``cargo`` that writes a
binary derived from SOURCE_DATE_EPOCH, the feature set, the target and the
REMAPPED working directory: two builds must match; a perturbed epoch on the
second build and an unremapped workspace path must each be reported as a
mismatch (the negative fixtures #3613 asks for).

Usage:
  scripts/release/reproducible_build.py --target T --features F --workspace-b DIR
      [--workspace-a DIR] [--bin NAME] [--epoch N] [--cargo PATH]
      [--nfpm PATH --nfpm-arch ARCH --version VERSION]
  scripts/release/reproducible_build.py --pack OUT --epoch N [--pack-root DIR] NAME...
  scripts/release/reproducible_build.py --sha256 FILE
  scripts/release/reproducible_build.py --pack-binary SRC --expect-sha256 HEX --copy-to DST --pack OUT --epoch N
  scripts/release/reproducible_build.py --verify-payload --expect-sha256 HEX PACKAGE...
  scripts/release/reproducible_build.py --self-test
Exit codes: 0 identical · 1 mismatch · 2 usage, build or git error.
"""
from __future__ import annotations

import argparse
import bz2
import hashlib
import gzip
import io
import lzma
import os
import re
import shutil
import stat
import struct
import tarfile
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath
from typing import Dict, List, Optional, Tuple

REMAP_SRC = "/src"
# #6291: the only caller variables a build sees (plus the overrides build_once sets).
BUILD_ENV_ALLOWLIST = ("PATH", "HOME", "CARGO_HOME", "RUSTUP_HOME", "RUSTUP_TOOLCHAIN", "TMPDIR")
# #6291: a compiler wrapper (a cache such as sccache) would let the second build reuse the first.
WRAPPER_VARS = ("RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "CARGO_BUILD_RUSTC_WRAPPER",
                "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER")
REMAP_CARGO = "/cargo"
CHUNK = 1 << 20
EPOCH_RE = re.compile(r"[0-9]+")
# #6283: the environment nfpm runs with in the proof (plus SOURCE_DATE_EPOCH, ARCH, VERSION).
NFPM_ENV_ALLOWLIST = ("PATH", "HOME", "TMPDIR")
NFPM_FORMATS = ("deb", "rpm")


class ProofError(Exception):
    """A step the proof needs failed (exit 2): not a mismatch, not a pass."""


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git(workspace: Path, *args: str) -> str:
    try:
        proc = subprocess.run(["git", "-C", str(workspace)] + list(args), capture_output=True, text=True, check=False)
    except OSError as exc:
        raise ProofError(f"cannot run git: {exc}") from exc
    if proc.returncode != 0:
        raise ProofError(f"git {' '.join(args)} in {workspace} exited {proc.returncode}: {proc.stderr.strip()[-300:]}")
    return proc.stdout.strip()


def epoch_of(workspace: Path) -> str:
    out = git(workspace, "log", "-1", "--format=%ct")
    if not out.isdigit():
        raise ProofError(f"git log -1 --format=%ct in {workspace} gave {out!r}, not an epoch")
    return out


def cargo_home() -> Path:
    return Path(os.environ.get("CARGO_HOME") or (Path.home() / ".cargo"))


def rustflags_for(workspace: Path, remap: bool) -> str:
    if not remap:
        return ""
    return f"--remap-path-prefix={workspace}={REMAP_SRC} --remap-path-prefix={cargo_home()}={REMAP_CARGO}"


def build_once(workspace: Path, target: str, features: str, epoch: str, cargo: str, remap: bool, bin_name: str) -> Path:
    """One release build in ``workspace``; returns the built binary's path.

    #6291: the build sees an allowlisted environment only, its own target
    directory and no compiler wrapper (an empty RUSTC_WRAPPER also overrides a
    ``build.rustc-wrapper`` from a cargo config file)."""
    wrapped = [k for k in WRAPPER_VARS if os.environ.get(k)]
    if wrapped:
        raise ProofError(f"{', '.join(wrapped)} is set: a compiler wrapper can serve the second build from the first "
                         "(unset it; the two builds must be independent)")
    env = {k: os.environ[k] for k in BUILD_ENV_ALLOWLIST if k in os.environ}
    env["SOURCE_DATE_EPOCH"] = epoch
    env["RUSTFLAGS"] = rustflags_for(workspace, remap)
    env["CARGO_TARGET_DIR"] = str(workspace / "target")
    env["CARGO_INCREMENTAL"] = "0"
    env["RUSTC_WRAPPER"] = ""
    env["RUSTC_WORKSPACE_WRAPPER"] = ""
    cmd = [cargo, "build", "--locked", "--release", "--target", target, "--features", features]
    print(f"reproducible-build: {workspace}: SOURCE_DATE_EPOCH={epoch} RUSTFLAGS={env['RUSTFLAGS']!r}", flush=True)
    print("reproducible-build: + " + " ".join(cmd), flush=True)
    try:
        proc = subprocess.run(cmd, cwd=workspace, env=env, check=False)
    except OSError as exc:
        raise ProofError(f"cannot run {cargo}: {exc}") from exc
    if proc.returncode != 0:
        raise ProofError(f"build in {workspace} exited {proc.returncode}")
    built = workspace / "target" / target / "release" / bin_name
    if not built.is_file():
        raise ProofError(f"build in {workspace} produced no {built}")
    return built


def ensure_workspace_b(workspace_a: Path, workspace_b: Path) -> None:
    """Workspace B is a fresh detached worktree of A's HEAD. #6291: an existing
    directory is accepted only when it is a checkout of exactly A's HEAD with no
    modified, untracked or ignored file (no earlier build output to reuse)."""
    if workspace_b.exists():
        head_a = git(workspace_a, "rev-parse", "--verify", "HEAD")
        head_b = git(workspace_b, "rev-parse", "--verify", "HEAD")
        if head_a != head_b:
            raise ProofError(f"workspace B {workspace_b} is at {head_b}, not workspace A's HEAD {head_a}")
        dirty = git(workspace_b, "status", "--porcelain", "--ignored", "--untracked-files=all")
        if dirty:
            raise ProofError(f"workspace B {workspace_b} is not a clean checkout (modified, untracked or ignored files: "
                             f"{dirty.splitlines()[0][:120]})")
        return
    workspace_b.parent.mkdir(parents=True, exist_ok=True)
    git(workspace_a, "worktree", "add", "--detach", str(workspace_b), "HEAD")


def _pack_entries(root: Path, names: List[str]) -> List[Tuple[str, Path, os.stat_result]]:
    """(arcname, path, lstat) for every NAME and everything under it, sorted by
    arcname. #6282: only regular files and directories are packed."""
    if not names:
        raise ProofError("--pack needs at least one name to pack")
    found = {}
    pending: List[Tuple[str, Path]] = []
    for name in names:
        rel = PurePosixPath(name)
        if rel.is_absolute() or not rel.parts or ".." in rel.parts or rel.parts == (".",) or "." in rel.parts:
            raise ProofError(f"--pack name {name!r} is not a plain relative path under the pack root")
        pending.append((rel.as_posix(), root.joinpath(*rel.parts)))
    while pending:
        arc, path = pending.pop()
        try:
            st = path.lstat()
        except OSError as exc:
            raise ProofError(f"--pack cannot read {path}: {exc}") from exc
        if arc in found:
            raise ProofError(f"--pack name {arc!r} is packed twice")
        if stat.S_ISDIR(st.st_mode):
            for child in path.iterdir():
                pending.append((f"{arc}/{child.name}", child))
        elif not stat.S_ISREG(st.st_mode):
            raise ProofError(f"--pack refuses {path}: not a regular file or directory (a link or special file)")
        found[arc] = (path, st)
    return [(arc, found[arc][0], found[arc][1]) for arc in sorted(found)]


def pack_tarball(out: Path, root: Path, names: List[str], epoch: str) -> str:
    """#6282: write a deterministic gzip tarball of ``names`` (relative to
    ``root``) to ``out`` and return its SHA-256. The bytes depend only on the
    file contents, the names, the executable bits and ``epoch``."""
    if not EPOCH_RE.fullmatch(epoch or ""):
        raise ProofError(f"--pack epoch {epoch!r} is not a non-negative integer (SOURCE_DATE_EPOCH must be set)")
    mtime = int(epoch)
    entries = _pack_entries(root, names)
    partial = out.with_name(out.name + ".partial")
    try:
        with open(partial, "wb") as raw:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=9) as gz:
                with tarfile.open(fileobj=gz, mode="w", format=tarfile.GNU_FORMAT) as tf:
                    for arc, path, st in entries:
                        info = tarfile.TarInfo(arc)
                        info.mtime = mtime
                        info.uid = info.gid = 0
                        info.uname = info.gname = ""
                        if stat.S_ISDIR(st.st_mode):
                            info.type = tarfile.DIRTYPE
                            info.mode = 0o755
                            tf.addfile(info)
                            continue
                        info.mode = 0o755 if st.st_mode & 0o111 else 0o644
                        info.size = st.st_size
                        with open(path, "rb") as fh:
                            tf.addfile(info, fh)
        os.replace(partial, out)
    except OSError as exc:
        raise ProofError(f"--pack cannot write {out}: {exc}") from exc
    finally:
        if partial.exists():
            partial.unlink()
    return sha256_of(out)


# #6907: the release job's package units read the asserted binary ONCE, through
# this module, and never through a PATH tool. ``read_once`` opens the file
# without following a final symlink, refuses anything but a regular file, and
# returns the bytes of that one open; every digest, archive and copy the package
# unit writes is computed from those bytes, so a file rewritten after the check
# cannot reach an artifact.
HEX64_RE = re.compile(r"[0-9a-f]{64}")
PACKAGED_PATH = "usr/bin/ai-memory"


def read_once(path: Path) -> bytes:
    """The bytes of the regular file ``path``, read through one descriptor."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(str(path), flags)
    except OSError as exc:
        raise ProofError(f"cannot open {path}: {exc}") from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ProofError(f"{path} is not a regular file")
        chunks = []
        while True:
            chunk = os.read(fd, CHUNK)
            if not chunk:
                break
            chunks.append(chunk)
    except OSError as exc:
        raise ProofError(f"cannot read {path}: {exc}") from exc
    finally:
        os.close(fd)
    return b"".join(chunks)


def expect_hex(value: Optional[str]) -> str:
    if value is None or not HEX64_RE.fullmatch(value):
        raise ProofError(f"--expect-sha256 {value!r} is not a lowercase SHA-256 hex digest")
    return value


def pack_binary(src: Path, expect: str, copy_to: Path, out: Path, epoch: str) -> str:
    """#6907: read ``src`` once, require its SHA-256 to be ``expect`` (the digest
    the strict assert recorded), then write the deterministic tarball (one member,
    ``copy_to.name``, mode 0755) and a fresh ``copy_to`` from those same bytes.
    Returns the tarball's SHA-256."""
    expect = expect_hex(expect)
    if not EPOCH_RE.fullmatch(epoch or ""):
        raise ProofError(f"--pack epoch {epoch!r} is not a non-negative integer (SOURCE_DATE_EPOCH must be set)")
    data = read_once(src)
    got = hashlib.sha256(data).hexdigest()
    if got != expect:
        raise ProofError(f"{src} ({got}) is not the binary the strict assert checked ({expect})")
    partial = out.with_name(out.name + ".partial")
    try:
        with open(partial, "wb") as raw:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=9) as gz:
                with tarfile.open(fileobj=gz, mode="w", format=tarfile.GNU_FORMAT) as tf:
                    info = tarfile.TarInfo(copy_to.name)
                    info.mtime = int(epoch)
                    info.uid = info.gid = 0
                    info.uname = info.gname = ""
                    info.mode = 0o755
                    info.size = len(data)
                    tf.addfile(info, io.BytesIO(data))
        os.replace(partial, out)
        if os.path.lexists(copy_to):
            os.unlink(copy_to)
        fd = os.open(str(copy_to), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o755)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.chmod(copy_to, 0o755)
    except OSError as exc:
        raise ProofError(f"--pack-binary cannot write {out} / {copy_to}: {exc}") from exc
    finally:
        if partial.exists():
            partial.unlink()
    return hashlib.sha256(read_once(out)).hexdigest()


# #7018 / #7019: what nfpm 2.41.1 writes for the pinned nfpm.yaml, probed on its
# real deb and rpm. Anything else in a package is refused rather than ignored:
# the check reads every member and header the package manager acts on, with one
# strict reader per format, so no second reader of the same bytes sees more.
PACKAGED_DIRS = ("usr", "usr/bin")
OWNER_NAMES = ("", "root")
TAR_MAGICS = (b"ustar  \x00", b"ustar\x0000")
DEB_MEMBERS = ("debian-binary", "control.tar.gz", "data.tar.gz")
DEB_CONTROL_MEMBERS = ("conffiles", "control", "md5sums")
DEB_CONTROL_FIELDS = ("Package", "Version", "Section", "Priority", "Architecture", "License", "Maintainer",
                      "Installed-Size", "Homepage", "Description")
RPM_TAGS = frozenset((63, 100, 1000, 1001, 1002, 1004, 1005, 1006, 1007, 1009, 1011, 1014, 1015, 1020, 1021, 1022,
                      1028, 1030, 1033, 1034, 1035, 1036, 1037, 1039, 1040, 1044, 1045, 1047, 1096, 1097, 1112, 1113,
                      1116, 1117, 1118, 1124, 1125, 1126, 5011, 5092, 5093))
RPM_REQUIRED_TAGS = (1028, 1030, 1035, 1036, 1037, 1039, 1040, 1116, 1117, 1118, 1124, 1125, 5011, 5092, 5093)
RPM_MAX_HEADER = 1 << 24
PAYLOAD_MAGIC = ((b"\x1f\x8b", "gzip"), (b"\xfd7zXZ\x00", "xz"), (b"BZh", "bzip2"))
SHA256_ALGO = 8
Entry = Tuple[str, str, int, bytes]


def _member(name: str, what: str) -> str:
    """A payload path without its leading ``./`` or ``/``; ``..`` is refused."""
    clean = name
    while clean.startswith("./"):
        clean = clean[2:]
    clean = clean.lstrip("/")
    if ".." in PurePosixPath(clean).parts:
        raise ProofError(f"{what}: payload entry {name!r} leaves the root")
    return PurePosixPath(clean).as_posix() if clean else "."


def _octal(field: bytes, what: str, label: str) -> int:
    digits = field.rstrip(b"\x00 ")
    if not digits or any(c not in b"01234567" for c in digits) or b"\x00" in digits:
        raise ProofError(f"{what}: tar header field {label} {field!r} is not a plain octal number")
    return int(digits, 8)


def _cstr(field: bytes, what: str, label: str) -> str:
    text, _, rest = field.partition(b"\x00")
    if rest.strip(b"\x00"):
        raise ProofError(f"{what}: tar header field {label} carries bytes after its terminator")
    try:
        return text.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProofError(f"{what}: tar header field {label} is not UTF-8") from exc


def _strict_tar(gz: bytes, what: str) -> List[Entry]:
    """#7019: the entries of a gzip tar, read with ONE strict reader: GNU / ustar
    regular files and directories only (no pax or GNU extension header, link,
    device or prefix field), every header checksum verified, root-owned by uid
    and by name, and nothing but zeros after the end-of-archive blocks. A
    member a more permissive reader would see differently is refused."""
    if not gz.startswith(b"\x1f\x8b"):
        raise ProofError(f"{what}: not a gzip stream")
    raw = _decompress(gz, what)
    out: List[Entry] = []
    seen = set()
    off = 0
    while True:
        hdr = raw[off:off + 512]
        if len(hdr) != 512:
            raise ProofError(f"{what}: tar ends at {off} without an end-of-archive block")
        if hdr == bytes(512):
            if len(raw) - off < 1024 or raw[off:].strip(b"\x00"):
                raise ProofError(f"{what}: tar end-of-archive at {off} is short or followed by data")
            return out
        if hdr[257:265] not in TAR_MAGICS or hdr[345:500].strip(b"\x00"):
            raise ProofError(f"{what}: tar header at {off} is not a plain GNU/ustar header")
        if _octal(hdr[148:156], what, "chksum") != sum(hdr[:148]) + 8 * 32 + sum(hdr[156:]):
            raise ProofError(f"{what}: tar header at {off} has a bad checksum")
        kind = {b"0": "f", b"5": "d"}.get(hdr[156:157])
        if kind is None or hdr[157:257].strip(b"\x00"):
            raise ProofError(f"{what}: tar entry at {off} (type {hdr[156:157]!r}) is not a regular file or directory "
                             "(links, devices and extension headers are refused)")
        name = _cstr(hdr[:100], what, "name")
        mode, uid, gid = (_octal(hdr[i:i + 8], what, lbl) for i, lbl in ((100, "mode"), (108, "uid"), (116, "gid")))
        size = _octal(hdr[124:136], what, "size")
        owners = (_cstr(hdr[265:297], what, "uname"), _cstr(hdr[297:329], what, "gname"))
        if uid or gid or any(o not in OWNER_NAMES for o in owners):
            raise ProofError(f"{what}: tar entry {name!r} is owned by {uid}:{gid} {owners}, not root")
        if kind == "d" and size:
            raise ProofError(f"{what}: tar directory {name!r} has data")
        data = raw[off + 512:off + 512 + size]
        if len(data) != size:
            raise ProofError(f"{what}: tar entry {name!r} is truncated")
        clean = _member(name, what)
        if clean in seen:
            raise ProofError(f"{what}: tar entry {name!r} appears twice")
        seen.add(clean)
        out.append((clean, kind, mode, data))
        off += 512 + (size + 511) // 512 * 512


def _payload_files(entries: List[Entry], what: str) -> Dict[str, Tuple[bytes, int, int]]:
    """#7018: the regular files of a payload; a directory must be one of
    PACKAGED_DIRS with mode 0755 (no other directory is created)."""
    files: Dict[str, Tuple[bytes, int, int]] = {}
    for name, kind, mode, data in entries:
        if kind == "d":
            if name not in PACKAGED_DIRS or mode != 0o755:
                raise ProofError(f"{what}: payload directory {name!r} (mode {oct(mode)}) is not one of {PACKAGED_DIRS} at 0755")
            continue
        files[name] = (data, mode, 1)
    return files


def _ar_members(blob: bytes, what: str) -> List[Tuple[str, bytes]]:
    """The members of an ar archive, read strictly: plain names, decimal sizes,
    newline padding and no byte after the last member."""
    if not blob.startswith(b"!<arch>\n"):
        raise ProofError(f"{what}: not an ar archive")
    out: List[Tuple[str, bytes]] = []
    off = 8
    while off < len(blob):
        hdr = blob[off:off + 60]
        if len(hdr) != 60 or hdr[58:60] != b"`\n":
            raise ProofError(f"{what}: truncated or malformed ar member header at {off}")
        name = hdr[:16].rstrip(b" ").decode("ascii", "replace")
        size_field = hdr[48:58].rstrip(b" ")
        if not size_field.isdigit():
            raise ProofError(f"{what}: ar member {name!r} has no decimal size")
        size = int(size_field)
        body = blob[off + 60:off + 60 + size]
        if len(body) != size:
            raise ProofError(f"{what}: ar member {name!r} is truncated")
        off += 60 + size
        if size & 1:
            if blob[off:off + 1] != b"\n":
                raise ProofError(f"{what}: ar member {name!r} is not newline-padded")
            off += 1
        out.append((name, body))
    return out


def _deb_control(text: bytes, what: str) -> None:
    """#7018: the control file holds only DEB_CONTROL_FIELDS (no dependency,
    Essential or other field), once each, for the package ai-memory."""
    fields: Dict[str, str] = {}
    last = ""
    try:
        lines = text.decode("utf-8").split("\n")
    except UnicodeDecodeError as exc:
        raise ProofError(f"{what}: control is not UTF-8") from exc
    if lines[-1] != "":
        raise ProofError(f"{what}: control does not end with a newline")
    for line in lines[:-1]:
        if line[:1] in (" ", "\t") and last == "Description":
            continue
        key, sep, value = line.partition(":")
        if not sep or key not in DEB_CONTROL_FIELDS or key in fields:
            raise ProofError(f"{what}: control line {line!r} is not one of the fields nfpm writes {DEB_CONTROL_FIELDS}")
        fields[key] = value.strip()
        last = key
    if fields.get("Package") != "ai-memory":
        raise ProofError(f"{what}: control names package {fields.get('Package')!r}, not 'ai-memory'")


def _deb_payload(blob: bytes, what: str) -> Dict[str, Tuple[bytes, int, int]]:
    """#7018: a deb is exactly debian-binary 2.0, control.tar.gz and data.tar.gz;
    control.tar holds exactly control (DEB_CONTROL_FIELDS), md5sums of the
    payload and an empty conffiles, and no maintainer script."""
    members = _ar_members(blob, what)
    names = tuple(n for n, _ in members)
    if names != DEB_MEMBERS:
        raise ProofError(f"{what}: ar members are {list(names)}, not {list(DEB_MEMBERS)}")
    if members[0][1] != b"2.0\n":
        raise ProofError(f"{what}: debian-binary is {members[0][1]!r}, not '2.0'")
    files = _payload_files(_strict_tar(members[2][1], what + " data.tar.gz"), what)
    control: Dict[str, bytes] = {}
    for name, kind, mode, data in _strict_tar(members[1][1], what + " control.tar.gz"):
        if kind != "f" or name not in DEB_CONTROL_MEMBERS or mode != 0o644:
            raise ProofError(f"{what}: control.tar member {name!r} is not one of {DEB_CONTROL_MEMBERS} at 0644 "
                             "(maintainer scripts are refused)")
        control[name] = data
    if tuple(sorted(control)) != DEB_CONTROL_MEMBERS:
        raise ProofError(f"{what}: control.tar holds {sorted(control)}, not {list(DEB_CONTROL_MEMBERS)}")
    _deb_control(control["control"], what)
    if control["conffiles"].strip():
        raise ProofError(f"{what}: conffiles is not empty")
    sums = b"".join(hashlib.md5(d, usedforsecurity=False).hexdigest().encode() + b"  ./" + n.encode() + b"\n"
                    for n, (d, _, _) in sorted(files.items()))
    if control["md5sums"] != sums:
        raise ProofError(f"{what}: md5sums does not list exactly the payload files")
    return files


def _rpm_header_end(blob: bytes, off: int, what: str, pad: bool) -> int:
    if blob[off:off + 3] != b"\x8e\xad\xe8":
        raise ProofError(f"{what}: no rpm header magic at {off}")
    if len(blob) < off + 16:
        raise ProofError(f"{what}: truncated rpm header at {off}")
    nindex, hsize = struct.unpack(">II", blob[off + 8:off + 16])
    end = off + 16 + 16 * nindex + hsize
    if end > len(blob):
        raise ProofError(f"{what}: rpm header at {off} runs past the end of the file")
    if pad:
        end += (-end) % 8
    return end


def _rpm_header(blob: bytes, off: int, what: str) -> Tuple[Dict[int, list], int]:
    """#7019: the tags of the rpm header at ``off`` (the header rpm installs
    from) and its end. int16 / int32 / string / binary / string-array values;
    any other type, a duplicate tag or an entry outside the store is refused."""
    end = _rpm_header_end(blob, off, what, pad=False)
    if blob[off:off + 8] != b"\x8e\xad\xe8\x01\x00\x00\x00\x00":
        raise ProofError(f"{what}: rpm header at {off} is not a version 1 header")
    nindex, hsize = struct.unpack(">II", blob[off + 8:off + 16])
    if hsize > RPM_MAX_HEADER:
        raise ProofError(f"{what}: rpm header at {off} is larger than {RPM_MAX_HEADER} bytes")
    store = blob[off + 16 + 16 * nindex:end]
    tags: Dict[int, list] = {}
    for i in range(nindex):
        tag, typ, at, count = struct.unpack(">iiii", blob[off + 16 + 16 * i:off + 32 + 16 * i])
        if tag in tags or at < 0 or count < 1 or at > len(store):
            raise ProofError(f"{what}: rpm header entry for tag {tag} is duplicated or out of range")
        if typ in (3, 4):
            width = 2 if typ == 3 else 4
            raw = store[at:at + width * count]
            if len(raw) != width * count:
                raise ProofError(f"{what}: rpm header tag {tag} runs past the store")
            tags[tag] = list(struct.unpack(">%d%s" % (count, "H" if typ == 3 else "i"), raw))
        elif typ == 7:
            if at + count > len(store):
                raise ProofError(f"{what}: rpm header tag {tag} runs past the store")
            tags[tag] = [store[at:at + count]]
        elif typ in (6, 8, 9) and (typ != 6 or count == 1):
            values, pos = [], at
            for _ in range(count):
                nul = store.find(b"\x00", pos)
                if nul < 0:
                    raise ProofError(f"{what}: rpm header tag {tag} has an unterminated string")
                values.append(store[pos:nul].decode("utf-8", "surrogateescape"))
                pos = nul + 1
            tags[tag] = values
        else:
            raise ProofError(f"{what}: rpm header tag {tag} has type {typ} / count {count}, which nfpm does not write")
    return tags, end


def _decompress(blob: bytes, what: str) -> bytes:
    try:
        if blob.startswith(b"\x1f\x8b"):
            return gzip.decompress(blob)
        if blob.startswith(b"\xfd7zXZ\x00"):
            return lzma.decompress(blob)
        if blob.startswith(b"BZh"):
            return bz2.decompress(blob)
    except (OSError, EOFError, lzma.LZMAError, ValueError) as exc:
        raise ProofError(f"{what}: payload does not decompress ({exc})") from exc
    raise ProofError(f"{what}: payload compression is not gzip, xz or bzip2 (refused rather than guessed)")


def _cpio_payload(blob: bytes, what: str) -> Dict[str, Tuple[bytes, int, int]]:
    """The regular files of a newc / crc cpio archive (an rpm payload): root-owned,
    one NUL-terminated name each, PACKAGED_DIRS only, zeros after the trailer."""
    entries: List[Entry] = []
    nlinks: Dict[str, int] = {}
    off = 0
    while True:
        hdr = blob[off:off + 110]
        if len(hdr) != 110 or hdr[:6] not in (b"070701", b"070702"):
            raise ProofError(f"{what}: malformed cpio header at {off}")
        try:
            f = [int(hdr[6 + 8 * i:14 + 8 * i], 16) for i in range(13)]
        except ValueError as exc:
            raise ProofError(f"{what}: malformed cpio header at {off}") from exc
        mode, uid, gid, nlink, size, namesize = f[1], f[2], f[3], f[4], f[6], f[11]
        nstart = off + 110
        raw_name = blob[nstart:nstart + namesize]
        if len(raw_name) != namesize or namesize < 2 or raw_name.index(b"\x00") != namesize - 1:
            raise ProofError(f"{what}: cpio name at {off} is not one NUL-terminated name")
        try:
            name = raw_name[:-1].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ProofError(f"{what}: cpio name at {off} is not UTF-8") from exc
        dstart = nstart + namesize
        dstart += (-dstart) % 4
        if name == "TRAILER!!!":
            if blob[dstart:].strip(b"\x00"):
                raise ProofError(f"{what}: data after the cpio trailer")
            files = _payload_files(entries, what)
            return {n: (d, m, nlinks[n]) for n, (d, m, _) in files.items()}
        data = blob[dstart:dstart + size]
        if len(data) != size:
            raise ProofError(f"{what}: cpio entry {name!r} is truncated")
        off = dstart + size
        off += (-off) % 4
        clean = _member(name, what)
        if uid or gid:
            raise ProofError(f"{what}: cpio entry {name!r} is owned by {uid}:{gid}, not root")
        if not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
            raise ProofError(f"{what}: payload entry {name!r} is not a regular file or directory")
        if clean in nlinks:
            raise ProofError(f"{what}: payload entry {name!r} appears twice")
        nlinks[clean] = nlink
        entries.append((clean, "d" if stat.S_ISDIR(mode) else "f", mode & 0o7777, data))


def _rpm_payload(blob: bytes, what: str) -> Dict[str, Tuple[bytes, int, int]]:
    """#7018 / #7019: the main header (what rpm installs from) carries only the
    tags nfpm writes (RPM_TAGS: no scriptlet, trigger, dependency or capability),
    its payload digest is that of the payload, and its file list, modes, owners,
    sizes and digests agree with the cpio entries."""
    if not blob.startswith(b"\xed\xab\xee\xdb"):
        raise ProofError(f"{what}: no rpm lead magic")
    sig_end = _rpm_header_end(blob, 96, what, pad=True)
    tags, main_end = _rpm_header(blob, sig_end, what)
    extra = sorted(set(tags) - RPM_TAGS)
    if extra:
        raise ProofError(f"{what}: rpm header carries tag(s) {extra} that nfpm does not write for nfpm.yaml "
                         "(scriptlets, triggers, dependencies and capabilities are refused)")
    missing = [t for t in RPM_REQUIRED_TAGS if t not in tags]
    if missing:
        raise ProofError(f"{what}: rpm header lacks tag(s) {missing}")
    body = blob[main_end:]
    comp = next((n for m, n in PAYLOAD_MAGIC if body.startswith(m)), None)
    if tags[1124] != ["cpio"] or tags[1125] != [comp] or tags[5093] != [SHA256_ALGO] \
            or tags[5092] != [hashlib.sha256(body).hexdigest()]:
        raise ProofError(f"{what}: rpm header payload format / compressor / digest does not describe the payload")
    files = _cpio_payload(_decompress(body, what), what)
    _only_binary(files, what)
    dirs, bases, index = tags[1118], tags[1117], tags[1116]
    if len(bases) != len(index) or any(not 0 <= i < len(dirs) for i in index):
        raise ProofError(f"{what}: rpm header file list is malformed")
    listed = [dirs[i] + b for i, b in zip(index, bases)]
    data = files[PACKAGED_PATH][0]
    want = {1030: [stat.S_IFREG | 0o755], 1036: [""], 1037: [0], 1039: ["root"], 1040: ["root"],
            5011: [SHA256_ALGO], 1028: [len(data)], 1035: [hashlib.sha256(data).hexdigest()]}
    if listed != ["/" + PACKAGED_PATH] or any(tags[t] != v for t, v in want.items()):
        raise ProofError(f"{what}: rpm header file list {listed} / modes / owners / sizes / digests do not "
                         f"describe the one checked file /{PACKAGED_PATH} at 0100755")
    return files


def _only_binary(files: Dict[str, Tuple[bytes, int, int]], what: str) -> None:
    if sorted(files) != [PACKAGED_PATH]:
        raise ProofError(f"{what}: payload files are {sorted(files)}, not exactly [{PACKAGED_PATH!r}]")
    _, mode, nlink = files[PACKAGED_PATH]
    if mode != 0o755 or nlink != 1:
        raise ProofError(f"{what}: {PACKAGED_PATH} has mode {oct(mode)} and {nlink} links, not 0o755 and 1")


def _verify_package(name: str, blob: bytes, expect: str, what: str) -> None:
    if name.endswith(".deb"):
        files = _deb_payload(blob, what)
    elif name.endswith(".rpm"):
        files = _rpm_payload(blob, what)
    else:
        raise ProofError(f"{what}: not a .deb or .rpm")
    _only_binary(files, what)
    got = hashlib.sha256(files[PACKAGED_PATH][0]).hexdigest()
    if got != expect:
        raise ProofError(f"{what}: {PACKAGED_PATH} ({got}) is not the binary the strict assert checked ({expect})")


def verify_payload(packages: List[Path], expect: str) -> None:
    """#6907 / #7018 / #7019: every deb / rpm is exactly what nfpm writes for
    nfpm.yaml around one regular file, ``usr/bin/ai-memory``, single-linked,
    mode 0755, root-owned, whose SHA-256 is ``expect`` (the asserted digest)."""
    expect = expect_hex(expect)
    if not packages:
        raise ProofError("--verify-payload needs at least one package")
    for pkg in packages:
        _verify_package(pkg.name, read_once(pkg), expect, str(pkg))


DIST_DEB_RE = re.compile(r"ai-memory_[0-9A-Za-z.+~]+_(?:amd64|arm64)\.deb")
DIST_RPM_RE = re.compile(r"ai-memory-[0-9A-Za-z.+~]+-1\.(?:x86_64|aarch64)\.rpm")


def verify_dist(dist: Path, tarball: str, expect: str) -> List[str]:
    """#7018: ``dist`` is what the checksum sweep, the provenance attestation and
    both upload steps publish (``dist/ai-memory*``). It must hold exactly the
    tarball (one root-owned 0755 member ``ai-memory`` with the asserted bytes),
    at most one deb and one rpm that pass the payload check, and the ``.sha256``
    sidecar of each, all regular files; each file is read once and its sidecar
    must name the digest of those bytes. Returns the checked artifact names."""
    expect = expect_hex(expect)
    try:
        names = sorted(os.listdir(dist))
    except OSError as exc:
        raise ProofError(f"cannot list {dist}: {exc}") from exc
    artifacts = [n for n in names if not n.endswith(".sha256")]
    debs = [n for n in artifacts if DIST_DEB_RE.fullmatch(n)]
    rpms = [n for n in artifacts if DIST_RPM_RE.fullmatch(n)]
    unknown = [n for n in artifacts if n != tarball and n not in debs and n not in rpms]
    if tarball not in artifacts or unknown or len(debs) > 1 or len(rpms) > 1:
        raise ProofError(f"{dist} holds {artifacts}: wanted {tarball!r} plus at most one deb and one rpm "
                         f"(unchecked: {unknown})")
    sidecars = [n for n in names if n.endswith(".sha256")]
    if sidecars != sorted(n + ".sha256" for n in artifacts):
        raise ProofError(f"{dist} sidecars {sidecars} are not exactly one .sha256 per artifact")
    for name in artifacts:
        what = str(dist / name)
        blob = read_once(dist / name)
        if name == tarball:
            entries = _strict_tar(blob, what)
            if [(n, k, m) for n, k, m, _ in entries] != [("ai-memory", "f", 0o755)] \
                    or hashlib.sha256(entries[0][3]).hexdigest() != expect:
                raise ProofError(f"{what}: is not one 0755 member 'ai-memory' holding the asserted binary ({expect})")
        else:
            _verify_package(name, blob, expect, what)
        line = f"{hashlib.sha256(blob).hexdigest()}  {name}\n".encode()
        if read_once(dist / (name + ".sha256")) != line:
            raise ProofError(f"{what}.sha256 does not name the SHA-256 of the checked {name}")
    return artifacts


# #6907 fixtures: the control file and rpm header nfpm 2.41.1 writes for nfpm.yaml.
DEB_CONTROL_FIXTURE = (b"Package: ai-memory\nVersion: 1.0.0\nSection: utils\nPriority: optional\n"
                       b"Architecture: amd64\nLicense: Apache-2.0\n"
                       b"Maintainer: AlphaOne LLC <alphaonedev@users.noreply.github.com>\nInstalled-Size: 0\n"
                       b"Homepage: https://alphaonedev.github.io/ai-memory-mcp/\n"
                       b"Description: AI-agnostic persistent memory system\n")
RPM_COMPRESSOR = {"gzip": "gzip", "xz": "xz", "bzip2": "bzip2", "zstd": "zstd"}


def _synthetic_tar(entries: List[Tuple[str, bytes, int, str]], uid: int = 0, uname: str = "root") -> bytes:
    """A gzip tar of (name, data, mode, kind) entries; kind is 'f', 'd' or 'l'."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz", format=tarfile.GNU_FORMAT) as tf:
        for name, data, mode, kind in entries:
            info = tarfile.TarInfo(name)
            info.mode = mode
            info.uid = info.gid = uid
            info.uname = info.gname = uname
            if kind == "d":
                info.type = tarfile.DIRTYPE
                tf.addfile(info)
            elif kind == "l":
                info.type = tarfile.SYMTYPE
                info.linkname = data.decode()
                tf.addfile(info)
            else:
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _rpm_header_bytes(tags: Dict[int, Tuple[int, list]]) -> bytes:
    """An rpm header structure (magic, index, store) holding ``tags``:
    tag -> (type, values); type 3 int16, 4 int32, 6 string, 7 bin, 8 string array."""
    index, store = b"", b""
    for tag in sorted(tags):
        typ, vals = tags[tag]
        if typ == 3:
            store += b"\x00" * ((-len(store)) % 2)
            body = b"".join(struct.pack(">H", v) for v in vals)
        elif typ == 4:
            store += b"\x00" * ((-len(store)) % 4)
            body = b"".join(struct.pack(">i", v) for v in vals)
        elif typ == 7:
            body = bytes(vals[0])
        else:
            body = b"".join(v.encode() + b"\x00" for v in vals)
        index += struct.pack(">iiii", tag, typ, len(store), len(body) if typ == 7 else len(vals))
        store += body
    return b"\x8e\xad\xe8\x01" + b"\x00" * 4 + struct.pack(">II", len(tags), len(store)) + index + store


def _synthetic_package(fmt: str, entries: List[Tuple[str, bytes, int, str]], nlink: int = 1,
                       compress: str = "gzip", data_members: int = 1,
                       control: Optional[Dict[str, Optional[bytes]]] = None, uid: int = 0, uname: str = "root",
                       tags: Optional[Dict[int, Optional[Tuple[int, list]]]] = None,
                       data_tar: Optional[bytes] = None) -> bytes:
    """#6907 self-test fixture: a deb (ar of debian-binary, control.tar.gz and
    data.tar.gz) or an rpm (lead, signature header, main header with nfpm's file
    and payload tags, compressed newc cpio) holding ``entries``. ``control``
    adds / replaces (None removes) control.tar members, ``tags`` main-header
    tags; ``data_tar`` replaces the deb data member. The layout is what nfpm
    writes; the self-test also runs on real nfpm output."""
    regular = [(n, d, m) for n, d, m, k in entries if k == "f"]
    if fmt == "deb":
        sums = b"".join(hashlib.md5(d).hexdigest().encode() + b"  " + n.encode() + b"\n"  # noqa: S324 (dpkg md5sums)
                        for n, d, _ in regular)
        ctl: Dict[str, Optional[bytes]] = {"./control": DEB_CONTROL_FIXTURE, "./md5sums": sums, "./conffiles": b"\n"}
        ctl.update(control or {})
        ctl_tar = _synthetic_tar([(n, b, 0o644, "f") for n, b in ctl.items() if b is not None], 0, "")
        data = data_tar if data_tar is not None else _synthetic_tar(entries, uid, uname)
        members = [("debian-binary", b"2.0\n"), ("control.tar.gz", ctl_tar)] + [("data.tar.gz", data)] * data_members
        out = b"!<arch>\n"
        for name, body in members:
            out += b"%-16s%-12s%-6s%-6s%-8s%-10d`\n" % (name.encode(), b"0", b"0", b"0", b"100644", len(body))
            out += body + (b"\n" if len(body) & 1 else b"")
        return out
    cpio = b""
    ino = 1
    for name, data, mode, kind in entries + [("TRAILER!!!", b"", 0, "t")]:
        ftype = {"f": stat.S_IFREG, "d": stat.S_IFDIR, "l": stat.S_IFLNK, "t": 0}[kind]
        nm = name.encode() + b"\x00"
        fields = [ino, ftype | mode, uid, uid, nlink if kind == "f" else 1, 0, len(data), 0, 0, 0, 0, len(nm), 0]
        hdr = b"070701" + b"".join(b"%08X" % v for v in fields) + nm
        cpio += hdr + b"\x00" * ((-len(hdr)) % 4) + data + b"\x00" * ((-len(data)) % 4)
        ino += 1
    payload = {"gzip": gzip.compress, "xz": lzma.compress, "bzip2": bz2.compress,
               "zstd": lambda b: b"\x28\xb5\x2f\xfd" + b}[compress](cpio)
    listed = [(n, d, m, k) for n, d, m, k in entries if k in ("f", "l")]
    paths = ["/" + n.lstrip(".").lstrip("/") for n, _, _, _ in listed]
    dirnames = sorted({q.rsplit("/", 1)[0] + "/" for q in paths})
    main: Dict[int, Tuple[int, list]] = {
        1000: (6, ["ai-memory"]), 1001: (6, ["1.0.0"]), 1002: (6, ["1"]), 1004: (6, ["ai-memory"]),
        1006: (4, [1700000000]), 1022: (6, ["x86_64"]),
        1028: (4, [len(d) for _, d, _, _ in listed]),
        1030: (3, [({"f": stat.S_IFREG, "l": stat.S_IFLNK}[k]) | m for _, _, m, k in listed]),
        1034: (4, [1700000000] * len(listed)),
        1035: (8, [hashlib.sha256(d).hexdigest() if k == "f" else "" for _, d, _, k in listed]),
        1036: (8, [d.decode() if k == "l" else "" for _, d, _, k in listed]),
        1037: (4, [0] * len(listed)), 1039: (8, ["root"] * len(listed)), 1040: (8, ["root"] * len(listed)),
        1116: (4, [dirnames.index(q.rsplit("/", 1)[0] + "/") for q in paths]),
        1117: (8, [q.rsplit("/", 1)[1] for q in paths]), 1118: (8, dirnames),
        1124: (6, ["cpio"]), 1125: (6, [RPM_COMPRESSOR[compress]]), 1126: (6, ["9"]),
        5011: (4, [8]), 5092: (8, [hashlib.sha256(payload).hexdigest()]), 5093: (4, [8]),
    }
    for tag, val in (tags or {}).items():
        if val is None:
            main.pop(tag, None)
        else:
            main[tag] = val
    sig = _rpm_header_bytes({1000: (4, [0])})
    sig += b"\x00" * ((-len(sig)) % 8)
    return b"\xed\xab\xee\xdb" + b"\x00" * 92 + sig + _rpm_header_bytes(main) + payload


def _gz_tar(build) -> bytes:
    """gzip of the raw tar ``build(tarfile)`` writes (a fixture with a pax header or a corrupt member)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tf:
        build(tf)
    return gzip.compress(buf.getvalue())


def _self_test_6907(tmp: Path) -> List[str]:
    """#6907 cases: the single-read pack and the deb/rpm payload check."""
    out: List[str] = []
    good, evil = b"the asserted bytes\n", b"bytes the assert never saw\n"
    want = hashlib.sha256(good).hexdigest()
    bin_entry = ("./usr/bin/ai-memory", good, 0o755, "f")
    dirs = [("./usr/", b"", 0o755, "d"), ("./usr/bin/", b"", 0o755, "d")]
    d = tmp / "6907"
    d.mkdir()

    def payload(name: str, ok: bool, fmt: str, entries: List[Tuple[str, bytes, int, str]], **kw: object) -> None:
        pkg = d / f"case.{fmt}"
        pkg.write_bytes(_synthetic_package(fmt, entries, **kw))  # type: ignore[arg-type]
        try:
            verify_payload([pkg], want)
            got = True
        except ProofError as exc:
            got = False
            print(f"self-test: {name}: {exc}", file=sys.stderr)
        if got != ok:
            out.append(f"{name}: {'accepted' if got else 'refused'}, wanted {'accepted' if ok else 'refused'}")

    for fmt in ("deb", "rpm"):
        payload(f"6907 {fmt} holding the asserted binary passes", True, fmt, dirs + [bin_entry])
        payload(f"6907 {fmt} holding other bytes is refused", False, fmt, dirs + [(bin_entry[0], evil, 0o755, "f")])
        payload(f"6907 {fmt} with a second file is refused", False, fmt, dirs + [bin_entry, ("./etc/x", b"", 0o644, "f")])
        payload(f"6907 {fmt} with a symlink is refused", False, fmt, dirs + [bin_entry, ("./usr/bin/am", b"ai-memory", 0o777, "l")])
        payload(f"6907 {fmt} binary not 0755 is refused", False, fmt, dirs + [(bin_entry[0], good, 0o4755, "f")])
        payload(f"6907 {fmt} with no binary is refused", False, fmt, dirs)
        payload(f"6907 {fmt} binary under another path is refused", False, fmt, [("./usr/bin/../bin/ai-memory", good, 0o755, "f")])
    payload("6907 deb with two data members is refused", False, "deb", dirs + [bin_entry], data_members=2)
    payload("6907 rpm binary with two links is refused", False, "rpm", dirs + [bin_entry], nlink=2)
    payload("6907 rpm xz payload holding the binary passes", True, "rpm", dirs + [bin_entry], compress="xz")
    payload("6907 rpm zstd payload is refused, not guessed", False, "rpm", dirs + [bin_entry], compress="zstd")
    # Class (a): an archive member or metadata the package manager acts on that
    # the payload check never looked at (maintainer scripts, dependencies,
    # conffiles, directories, ownership, file capabilities).
    ctl = DEB_CONTROL_FIXTURE
    payload("6907a deb with a postinst maintainer script is refused", False, "deb", dirs + [bin_entry],
            control={"./postinst": b"#!/bin/sh\nexit 0\n"})
    payload("6907a deb control declaring Pre-Depends is refused", False, "deb", dirs + [bin_entry],
            control={"./control": ctl + b"Pre-Depends: other\n"})
    payload("6907a deb control naming another package is refused", False, "deb", dirs + [bin_entry],
            control={"./control": ctl.replace(b"Package: ai-memory", b"Package: libc6")})
    payload("6907a deb marking the binary a conffile is refused", False, "deb", dirs + [bin_entry],
            control={"./conffiles": b"/usr/bin/ai-memory\n"})
    payload("6907a deb md5sums of other bytes is refused", False, "deb", dirs + [bin_entry],
            control={"./md5sums": hashlib.md5(evil).hexdigest().encode() + b"  ./usr/bin/ai-memory\n"})  # noqa: S324
    payload("6907a deb creating another directory is refused", False, "deb",
            dirs + [("./etc/", b"", 0o755, "d"), ("./etc/cron.d/", b"", 0o777, "d"), bin_entry])
    payload("6907a deb binary owned by a non-root uid is refused", False, "deb", dirs + [bin_entry], uid=1000)
    payload("6907a rpm with a %post scriptlet is refused", False, "rpm", dirs + [bin_entry],
            tags={1024: (6, ["exit 0"]), 1086: (6, ["/bin/sh"])})
    payload("6907a rpm requiring another package is refused", False, "rpm", dirs + [bin_entry],
            tags={1048: (4, [0]), 1049: (8, ["other"]), 1050: (8, [""])})
    payload("6907a rpm granting a file capability is refused", False, "rpm", dirs + [bin_entry],
            tags={5010: (8, ["cap_setuid=ep"])})
    # Class (b): two readers of the same bytes that disagree. rpm installs from
    # its header (file list, modes, owners, digests), dpkg resolves owners by
    # name and honours tar extension headers its own way; the check must read
    # the same thing the installer acts on, or refuse.
    payload("6907b rpm header mode 04755 over a 0755 cpio entry is refused", False, "rpm", dirs + [bin_entry],
            tags={1030: (3, [stat.S_IFREG | 0o4755])})
    payload("6907b rpm header naming another file is refused", False, "rpm", dirs + [bin_entry],
            tags={1117: (8, ["other"])})
    payload("6907b rpm header digest of other bytes is refused", False, "rpm", dirs + [bin_entry],
            tags={1035: (8, [hashlib.sha256(evil).hexdigest()])})
    payload("6907b rpm header owner not root is refused", False, "rpm", dirs + [bin_entry],
            tags={1039: (8, ["nobody"])})
    payload("6907b rpm payload digest of other bytes is refused", False, "rpm", dirs + [bin_entry],
            tags={5092: (8, [hashlib.sha256(evil).hexdigest()])})
    payload("6907b deb binary owner name not root is refused", False, "deb", dirs + [bin_entry], uname="www-data")

    def pax_rename(tf: tarfile.TarFile) -> None:
        info = tarfile.TarInfo("./usr/bin/other")
        info.size, info.mode = len(good), 0o755
        info.pax_headers = {"path": "./usr/bin/ai-memory"}
        tf.addfile(info, io.BytesIO(good))

    def corrupt_tail(tf: tarfile.TarFile) -> None:
        info = tarfile.TarInfo("./usr/bin/ai-memory")
        info.size, info.mode = len(good), 0o755
        tf.addfile(info, io.BytesIO(good))
        hidden = io.BytesIO()
        with tarfile.open(fileobj=hidden, mode="w", format=tarfile.GNU_FORMAT) as h:
            extra = tarfile.TarInfo("./etc/hidden")
            extra.size, extra.mode = len(evil), 0o644
            h.addfile(extra, io.BytesIO(evil))
        raw = bytearray(hidden.getvalue()[:1024])
        raw[148:156] = b"0000000\x00"
        tf.fileobj.write(bytes(raw))
        tf.offset += len(raw)

    payload("6907b deb pax header renaming a member is refused", False, "deb", dirs + [bin_entry],
            data_tar=_gz_tar(pax_rename))
    payload("6907b deb member past a corrupt tar header is refused", False, "deb", dirs + [bin_entry],
            data_tar=_gz_tar(corrupt_tail))
    junk = d / "junk.rpm"
    junk.write_bytes(b"\xed\xab\xee\xdb" + b"\x00" * 10)
    for name, call in (("6907 a truncated rpm is refused", lambda: verify_payload([junk], want)),
                       ("6907 a non-hex expected digest is refused", lambda: verify_payload([junk], "Z" * 64)),
                       ("6907 no package at all is refused", lambda: verify_payload([], want))):
        try:
            call()
            out.append(f"{name}: accepted")
        except ProofError:
            pass

    src, copy, tgz = d / "bin", d / "dist-ai-memory", d / "out.tar.gz"
    src.write_bytes(good)
    decoy = d / "decoy"
    decoy.write_bytes(b"decoy\n")
    copy.symlink_to(decoy)
    try:
        pack_binary(src, want, copy, tgz, "1700000000")
        with tarfile.open(tgz) as tf:
            members = tf.getmembers()
            fh = tf.extractfile(members[0]) if len(members) == 1 else None
            packed = fh.read() if fh is not None else None
        if packed != good or members[0].mode != 0o755 or members[0].name != copy.name:
            out.append("6907 pack_binary did not pack the asserted bytes as one 0755 member")
        if copy.is_symlink() or copy.read_bytes() != good or decoy.read_bytes() != b"decoy\n":
            out.append("6907 pack_binary followed a planted link or did not write the asserted bytes")
    except ProofError as exc:
        out.append(f"6907 pack_binary refused the asserted binary: {exc}")
    for i, (name, s) in enumerate((("6907 pack_binary refuses bytes the assert did not check", evil),
                                   ("6907 pack_binary refuses a symlinked source", None))):
        if tgz.exists():
            tgz.unlink()
        other = d / f"src-{i}"
        if s is None:
            other.symlink_to(src)
        else:
            other.write_bytes(s)
        try:
            pack_binary(other, want, copy, tgz, "1700000000")
            out.append(f"{name}: accepted")
        except ProofError:
            if tgz.exists():
                out.append(f"{name}: refused but still wrote {tgz.name}")
    fifo = d / "fifo"
    os.mkfifo(fifo)
    try:
        read_once(fifo)
        out.append("6907 read_once accepted a FIFO")
    except ProofError:
        pass
    return out


def nfpm_packages(workspace: Path, binary: Path, nfpm: str, arch: str, version: str, epoch: str) -> List[Tuple[str, str]]:
    """#6283: build the deb and rpm of ``binary`` in ``workspace`` the way the
    release job does (``nfpm.yaml``, ``dist/ai-memory``) and return the sorted
    (file name, SHA-256) pairs."""
    dist = workspace / "dist"
    outdir = workspace / "target" / "reproducible-nfpm"
    shutil.rmtree(outdir, ignore_errors=True)
    try:
        dist.mkdir(exist_ok=True)
        outdir.mkdir(parents=True)
        shutil.copyfile(binary, dist / "ai-memory")
        (dist / "ai-memory").chmod(0o755)
    except OSError as exc:
        raise ProofError(f"cannot stage dist/ai-memory in {workspace}: {exc}") from exc
    env = {k: os.environ[k] for k in NFPM_ENV_ALLOWLIST if k in os.environ}
    env.update({"SOURCE_DATE_EPOCH": epoch, "ARCH": arch, "VERSION": version})
    for fmt in NFPM_FORMATS:
        cmd = [nfpm, "package", "-p", fmt, "-f", "nfpm.yaml", "-t", str(outdir)]
        print("reproducible-build: + " + " ".join(cmd), flush=True)
        try:
            proc = subprocess.run(cmd, cwd=workspace, env=env, check=False)
        except OSError as exc:
            raise ProofError(f"cannot run {nfpm}: {exc}") from exc
        if proc.returncode != 0:
            raise ProofError(f"nfpm {fmt} in {workspace} exited {proc.returncode}")
    built = sorted(p for p in outdir.iterdir() if p.is_file())
    if len(built) != len(NFPM_FORMATS):
        raise ProofError(f"nfpm in {workspace} produced {len(built)} packages, wanted {len(NFPM_FORMATS)}")
    return [(p.name, sha256_of(p)) for p in built]


def differing(a: bytes, b: bytes) -> Tuple[int, int]:
    """(count of differing bytes over the common prefix, first differing offset or -1)."""
    n = min(len(a), len(b))
    first = -1
    count = 0
    for i in range(n):
        if a[i] != b[i]:
            count += 1
            if first < 0:
                first = i
    return count, first


def describe_mismatch(bin_a: Path, bin_b: Path) -> None:
    data_a, data_b = bin_a.read_bytes(), bin_b.read_bytes()
    count, first = differing(data_a, data_b)
    print(f"reproducible-build: sizes {len(data_a)} vs {len(data_b)} bytes; {count} differing bytes over the common "
          f"prefix; first differing offset {first:#x}" if first >= 0 else
          f"reproducible-build: sizes {len(data_a)} vs {len(data_b)} bytes; common prefix identical", flush=True)
    for label, path in (("A", bin_a), ("B", bin_b)):
        if shutil.which("readelf") and path.read_bytes()[:4] == b"\x7fELF":
            print(f"reproducible-build: ELF sections of {label} ({path}):", flush=True)
            subprocess.run(["readelf", "-S", "-W", str(path)], check=False)
    if shutil.which("diffoscope"):
        print("reproducible-build: diffoscope summary:", flush=True)
        subprocess.run(["diffoscope", "--max-report-size", "200000", str(bin_a), str(bin_b)], check=False)
    else:
        print("reproducible-build: diffoscope not installed; install it for a per-section diff", flush=True)


def two_builds(workspace_a: Path, workspace_b: Path, target: str, features: str, bin_name: str, cargo: str,
               epoch: Optional[str] = None, epoch_b: Optional[str] = None, remap: bool = True,
               sha256_output: Optional[Path] = None, pack_epoch_b: Optional[str] = None,
               nfpm: Optional[str] = None, nfpm_arch: Optional[str] = None, version: Optional[str] = None,
               nfpm_epoch_b: Optional[str] = None) -> int:
    """Build in both workspaces and compare the binaries, their tarballs and
    (with ``nfpm``) their deb and rpm packages. Returns the exit code (0 / 1).
    ``epoch_b``, ``remap=False``, ``pack_epoch_b`` and ``nfpm_epoch_b`` exist for
    the negative fixtures only."""
    if not features.strip():
        raise ProofError("--features is empty (the release feature declaration came back empty: fail closed)")
    if nfpm is not None and (not version or not nfpm_arch):
        raise ProofError("--nfpm needs a non-empty --version and --nfpm-arch (fail closed)")
    epoch_a = epoch if epoch is not None else epoch_of(workspace_a)
    ensure_workspace_b(workspace_a, workspace_b)
    bin_a = build_once(workspace_a, target, features, epoch_a, cargo, remap, bin_name)
    bin_b = build_once(workspace_b, target, features, epoch_b if epoch_b is not None else epoch_a, cargo, remap, bin_name)
    sha_a, sha_b = sha256_of(bin_a), sha256_of(bin_b)
    print(f"reproducible-build: workspace A {bin_a} sha256={sha_a}", flush=True)
    print(f"reproducible-build: workspace B {bin_b} sha256={sha_b}", flush=True)
    if sha_a != sha_b:
        print(f"::error::reproducible-build: MISMATCH: two builds of {bin_name} for {target} from the same commit differ "
              f"({sha_a} vs {sha_b}); the build is not reproducible (#3613)", flush=True)
        describe_mismatch(bin_a, bin_b)
        return 1
    # #6283: the shipped form is the tarball (and the deb/rpm), not the bare binary.
    tar_name = f"{bin_name}-{target}.tar.gz"
    tars = []
    for ws, bin_path, pack_epoch in ((workspace_a, bin_a, epoch_a),
                                     (workspace_b, bin_b, pack_epoch_b if pack_epoch_b is not None else epoch_a)):
        pack_dir = ws / "target" / "reproducible-pack"
        pack_dir.mkdir(parents=True, exist_ok=True)
        tars.append(pack_tarball(pack_dir / tar_name, bin_path.parent, [bin_name], pack_epoch))
    print(f"reproducible-build: tarballs {tar_name} sha256 A={tars[0]} B={tars[1]}", flush=True)
    if tars[0] != tars[1]:
        print(f"::error::reproducible-build: MISMATCH: the tarballs of two identical builds differ ({tars[0]} vs "
              f"{tars[1]}); packaging is not reproducible (#6283)", flush=True)
        return 1
    if nfpm is not None:
        pkgs_a = nfpm_packages(workspace_a, bin_a, nfpm, nfpm_arch or "", version or "", epoch_a)
        pkgs_b = nfpm_packages(workspace_b, bin_b, nfpm, nfpm_arch or "", version or "",
                               nfpm_epoch_b if nfpm_epoch_b is not None else epoch_a)
        print(f"reproducible-build: packages A={pkgs_a} B={pkgs_b}", flush=True)
        if pkgs_a != pkgs_b:
            print("::error::reproducible-build: MISMATCH: the deb/rpm packages of two identical builds differ; "
                  "packaging is not reproducible (#6283)", flush=True)
            return 1
    print(f"reproducible-build: OK (two builds of {bin_name} for {target} are byte-identical: {sha_a}; tarballs"
          f"{' and deb/rpm' if nfpm is not None else ''} identical)", flush=True)
    if sha256_output is not None:
        # #6274: the proven digest, for the release job's shipped-binary compare.
        with open(sha256_output, "a", encoding="utf-8") as fh:
            fh.write(f"sha256={sha_a}\n")
    return 0


# ------------------------------------------------------------- self-test --
STUB_CARGO = '''#!/usr/bin/env python3
"""Stub cargo for reproducible_build.py --self-test: writes a 'binary' that is a
function of SOURCE_DATE_EPOCH, the features, the target and the working
directory AS REMAPPED by RUSTFLAGS (a path that is not remapped leaks)."""
import os
import pathlib
import sys

args = sys.argv[1:]
target = args[args.index("--target") + 1]
features = args[args.index("--features") + 1]
cwd = os.getcwd()
for flag in os.environ.get("RUSTFLAGS", "").split():
    if flag.startswith("--remap-path-prefix="):
        src, dst = flag[len("--remap-path-prefix="):].split("=", 1)
        if cwd.startswith(src):
            cwd = dst + cwd[len(src):]
# Like cargo: CARGO_TARGET_DIR (when set) decides where the output lands, and a
# caller variable that reaches the build is visible in what it produces.
out = pathlib.Path(os.environ.get("CARGO_TARGET_DIR") or "target") / target / "release" / "ai-memory"
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text("epoch=%s features=%s target=%s cwd=%s leak=%s\\n" % (
    os.environ.get("SOURCE_DATE_EPOCH"), features, target, cwd, os.environ.get("REPRO_SELFTEST_LEAK")))
'''


SELF_TEST_CLEARED = ("CARGO_TARGET_DIR", "CARGO_BUILD_TARGET_DIR", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER",
                     "CARGO_BUILD_RUSTC_WRAPPER", "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER", "REPRO_SELFTEST_LEAK")


def self_test(root: Path) -> int:
    """Run the cases with the cargo variables a developer shell may carry cleared
    (each case that needs one sets it), and restore them afterwards."""
    saved = {k: os.environ.pop(k) for k in SELF_TEST_CLEARED if k in os.environ}
    try:
        return _self_test(root)
    finally:
        os.environ.update(saved)


def _self_test(root: Path) -> int:
    base = os.environ.get("TMPDIR") or str(root / ".local-runs")
    Path(base).mkdir(parents=True, exist_ok=True)
    failures: List[str] = []
    with tempfile.TemporaryDirectory(prefix="repro-selftest.", dir=base) as td:
        tmp = Path(td)
        stub = tmp / "bin" / "cargo"
        stub.parent.mkdir()
        stub.write_text(STUB_CARGO, encoding="utf-8")
        stub.chmod(0o755)
        ws_a, ws_b = tmp / "workspace-a", tmp / "workspace-b"

        def g(ws: Path, *args: str) -> None:
            subprocess.run(["git", "-C", str(ws), "-c", "user.name=selftest", "-c", "user.email=selftest@invalid",
                            "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null"] + list(args),
                           check=True, capture_output=True)

        def fresh() -> None:
            # A is a one-commit repository; B does not exist (the proof creates it
            # as a detached worktree of A's HEAD).
            for ws in (ws_a, ws_b):
                shutil.rmtree(ws, ignore_errors=True)
            ws_a.mkdir()
            g(ws_a, "init", "-q")
            (ws_a / "src.txt").write_text("one\n", encoding="utf-8")
            g(ws_a, "add", "src.txt")
            g(ws_a, "commit", "-q", "-m", "one")

        def run(name: str, want: int, **kwargs: object) -> None:
            fresh()
            try:
                got = two_builds(ws_a, ws_b, "x86_64-unknown-linux-gnu", "sal,sal-postgres", "ai-memory", str(stub),
                                 epoch="1700000000", **kwargs)  # type: ignore[arg-type]
            except ProofError as exc:
                got = 2
                print(f"self-test: {name}: {exc}", file=sys.stderr)
            if got != want:
                failures.append(f"{name}: exit {got}, wanted {want}")

        run("two identical builds pass", 0)

        # --- #6291: the two builds are independent.
        def run_prepared(name: str, want: int, prepare, env: Optional[dict] = None, check=None) -> None:
            fresh()
            prepare()
            saved = {k: os.environ.get(k) for k in (env or {})}
            os.environ.update(env or {})
            try:
                got = two_builds(ws_a, ws_b, "x86_64-unknown-linux-gnu", "sal,sal-postgres", "ai-memory", str(stub),
                                 epoch="1700000000")
            except ProofError as exc:
                got = 2
                print(f"self-test: {name}: {exc}", file=sys.stderr)
            finally:
                for k, v in saved.items():
                    if v is None:
                        os.environ.pop(k, None)
                    else:
                        os.environ[k] = v
            if got != want:
                failures.append(f"{name}: exit {got}, wanted {want}")
            elif check is not None and not check():
                failures.append(f"{name}: the build output shows the caller environment reached it")

        def b_at_older_commit() -> None:
            g(ws_a, "worktree", "add", "-q", "--detach", str(ws_b), "HEAD")
            (ws_a / "src.txt").write_text("two\n", encoding="utf-8")
            g(ws_a, "commit", "-q", "-am", "two")

        def b_dirty() -> None:
            g(ws_a, "worktree", "add", "-q", "--detach", str(ws_b), "HEAD")
            (ws_b / "src.txt").write_text("seeded\n", encoding="utf-8")

        def b_prebuilt() -> None:
            g(ws_a, "worktree", "add", "-q", "--detach", str(ws_b), "HEAD")
            (ws_b / "target").mkdir()
            (ws_b / "target" / "seed").write_text("cached\n", encoding="utf-8")

        def nothing() -> None:
            pass

        def a_output_clean() -> bool:
            built = ws_a / "target" / "x86_64-unknown-linux-gnu" / "release" / "ai-memory"
            return built.is_file() and "leak=None" in built.read_text(encoding="utf-8")

        run_prepared("6291 an existing workspace B at another commit is refused", 2, b_at_older_commit)
        run_prepared("6291 an existing workspace B with a modified file is refused", 2, b_dirty)
        run_prepared("6291 an existing workspace B holding build output is refused", 2, b_prebuilt)
        run_prepared("6291 RUSTC_WRAPPER in the caller environment is refused", 2, nothing,
                     {"RUSTC_WRAPPER": "/usr/bin/true"})
        run_prepared("6291 RUSTC_WORKSPACE_WRAPPER in the caller environment is refused", 2, nothing,
                     {"RUSTC_WORKSPACE_WRAPPER": "/usr/bin/true"})
        run_prepared("6291 a caller CARGO_TARGET_DIR does not redirect the builds", 0, nothing,
                     {"CARGO_TARGET_DIR": str(tmp / "shared-target")})
        run_prepared("6291 a caller variable outside the allowlist does not reach the build", 0, nothing,
                     {"REPRO_SELFTEST_LEAK": "1"}, a_output_clean)
        run("a perturbed SOURCE_DATE_EPOCH on the second build is a mismatch", 1, epoch_b="1700000001")
        run("an unremapped workspace path is a mismatch", 1, remap=False)
        fresh()
        try:
            two_builds(ws_a, ws_b, "x86_64-unknown-linux-gnu", "", "ai-memory", str(stub), epoch="1700000000")
            failures.append("an empty feature set was accepted (fail-open)")
        except ProofError:
            pass
        # #6274: on success the CLI appends the proven digest to --sha256-output
        # (the job's GITHUB_OUTPUT), which the release job compares with the
        # shipped binary's hash.
        fresh()
        out = tmp / "github-output"
        out.write_text("earlier=1\n", encoding="utf-8")
        try:
            rc = main(["--target", "x86_64-unknown-linux-gnu", "--features", "sal", "--workspace-a", str(ws_a),
                       "--workspace-b", str(ws_b), "--cargo", str(stub), "--epoch", "1", "--sha256-output", str(out)])
        except SystemExit as exc:
            rc = exc.code if isinstance(exc.code, int) else 2
        built = ws_a / "target" / "x86_64-unknown-linux-gnu" / "release" / "ai-memory"
        want = "earlier=1\nsha256=" + (sha256_of(built) if built.is_file() else "?") + "\n"
        if rc != 0 or out.read_text(encoding="utf-8") != want:
            failures.append(f"--sha256-output did not record the proven digest (exit {rc})")
        fresh()
        try:
            two_builds(ws_a, ws_b, "x86_64-unknown-linux-gnu", "sal", "ai-memory", str(tmp / "no-such-cargo"), epoch="1")
            failures.append("a missing build tool was not an error")
        except ProofError:
            pass
        failures.extend(_self_test_6282(tmp, ws_a, ws_b, stub, g, fresh))
        failures.extend(_self_test_6907(tmp))
    for f in failures:
        print(f"reproducible_build: self-test FAIL: {f}", file=sys.stderr)
    if failures:
        return 1
    print("reproducible_build: self-test OK (identical builds pass; perturbed epoch, unremapped path, empty feature set "
          "and missing build tool are refused; a stale, dirty or prebuilt workspace B, a compiler wrapper and caller "
          "environment leaks are refused, #6291; the packed tarball and the deb/rpm are compared and a "
          "perturbed packing epoch is refused, #6282/#6283; the single-read pack and the deb/rpm payload check refuse "
          "bytes the strict assert did not check, #6907)")
    return 0


STUB_NFPM = '''#!/usr/bin/env python3
"""Stub nfpm for reproducible_build.py --self-test: writes a 'package' that is a
function of the packaged binary, SOURCE_DATE_EPOCH, ARCH, VERSION and the format."""
import hashlib
import os
import pathlib
import sys

args = sys.argv[1:]
fmt = args[args.index("-p") + 1]
outdir = pathlib.Path(args[args.index("-t") + 1])
binary = hashlib.sha256(pathlib.Path("dist/ai-memory").read_bytes()).hexdigest()
outdir.mkdir(parents=True, exist_ok=True)
name = "ai-memory_%s_%s.%s" % (os.environ["VERSION"], os.environ["ARCH"], fmt)
(outdir / name).write_text("bin=%s epoch=%s fmt=%s\\n" % (binary, os.environ.get("SOURCE_DATE_EPOCH"), fmt))
'''


def _self_test_6282(tmp: Path, ws_a: Path, ws_b: Path, stub: Path, g, fresh) -> List[str]:
    """#6282 / #6283 cases: the deterministic packer, and the tarball and deb/rpm
    comparisons of the two-build proof."""
    import tarfile
    out: List[str] = []
    pack = globals().get("pack_tarball")
    if pack is None:
        return ["6282 pack_tarball (the deterministic packer) is missing"]
    src = tmp / "pack-src"

    def tree(stamp: int, reverse: bool) -> None:
        shutil.rmtree(src, ignore_errors=True)
        files = [("d/b.txt", b"b\n", 0o644), ("d/a.bin", b"a\n", 0o755), ("top", b"t\n", 0o600)]
        for rel, data, mode in (reversed(files) if reverse else files):
            p = src / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(data)
            p.chmod(mode)
            os.utime(p, (stamp, stamp))
        os.utime(src / "d", (stamp, stamp))

    def packed(name: str, epoch: str) -> bytes:
        dst = tmp / name
        pack(dst, src, ["d", "top"], epoch)
        return dst.read_bytes()

    tree(1111111111, False)
    one = packed("one.tar.gz", "1700000000")
    tree(1222222222, True)
    two = packed("two.tar.gz", "1700000000")
    if one != two:
        out.append("6282 pack: file mtimes or creation order changed the archive bytes")
    if packed("three.tar.gz", "1700000001") == one:
        out.append("6282 pack: a different epoch gave the same archive (the epoch is not recorded)")
    with tarfile.open(tmp / "one.tar.gz", "r:gz") as tf:
        members = tf.getmembers()
        names = [m.name for m in members]
        if names != sorted(names) or names[:1] != ["d"]:
            out.append(f"6282 pack: members are not in sorted order: {names}")
        for m in members:
            if (m.mtime, m.uid, m.gid, m.uname, m.gname) != (1700000000, 0, 0, "", ""):
                out.append(f"6282 pack: {m.name} carries a build-host mtime or owner")
            want = 0o755 if m.isdir() or m.name == "d/a.bin" else 0o644
            if m.mode != want:
                out.append(f"6282 pack: {m.name} mode {oct(m.mode)}, wanted {oct(want)}")
    if one[4:8] != b"\0\0\0\0" or one[3] & 0x08:
        out.append("6282 pack: the gzip header carries a timestamp or a file name")
    for bad_names, bad_epoch, why in ((["/etc"], "1", "an absolute name"), (["../x"], "1", "a name outside the root"),
                                      (["d"], "", "an empty epoch"), (["d"], "x1", "a non-numeric epoch"),
                                      (["missing"], "1", "a missing name"), ([], "1", "no name")):
        try:
            pack(tmp / "bad.tar.gz", src, bad_names, bad_epoch)
            out.append(f"6282 pack: {why} was accepted")
        except ProofError:
            pass
    (src / "link").symlink_to("top")
    try:
        pack(tmp / "bad.tar.gz", src, ["link"], "1")
        out.append("6282 pack: a symbolic link was packed")
    except ProofError:
        pass
    cwd = os.getcwd()
    try:
        os.chdir(src)
        rc = main(["--pack", str(tmp / "cli.tar.gz"), "--epoch", "1700000000", "d", "top"])
    finally:
        os.chdir(cwd)
    if rc != 0 or (tmp / "cli.tar.gz").read_bytes() != one:
        out.append(f"6282 pack CLI did not write the same archive (exit {rc})")

    # #6283: the proof compares the tarball of each build and, with --nfpm, the deb/rpm.
    nfpm = tmp / "bin" / "nfpm"
    nfpm.write_text(STUB_NFPM, encoding="utf-8")
    nfpm.chmod(0o755)

    def proof(name: str, want: int, **kwargs: object) -> None:
        fresh()
        try:
            got = two_builds(ws_a, ws_b, "x86_64-unknown-linux-gnu", "sal", "ai-memory", str(stub), epoch="1700000000",
                             **kwargs)  # type: ignore[arg-type]
        except ProofError as exc:
            got = 2
            print(f"self-test: {name}: {exc}", file=sys.stderr)
        except TypeError as exc:
            got = -1
            print(f"self-test: {name}: {exc}", file=sys.stderr)
        if got != want:
            out.append(f"{name}: exit {got}, wanted {want}")

    proof("6283 identical builds give identical tarballs", 0)
    proof("6283 a tarball packed with another epoch is a mismatch", 1, pack_epoch_b="1700000001")
    nf = {"nfpm": str(nfpm), "nfpm_arch": "amd64", "version": "1.0.0"}
    proof("6283 identical builds give identical deb and rpm", 0, **nf)
    proof("6283 a deb/rpm built with another epoch is a mismatch", 1, nfpm_epoch_b="1700000001", **nf)
    proof("6283 a missing nfpm is an error", 2, nfpm=str(tmp / "no-such-nfpm"), nfpm_arch="amd64", version="1.0.0")
    proof("6283 --nfpm without a version is an error", 2, nfpm=str(nfpm), nfpm_arch="amd64", version="")
    return out


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Two-build byte-identity proof of a release binary (#3613).")
    ap.add_argument("--target", help="cargo --target triple (the release matrix leg being proven)")
    ap.add_argument("--features", help="the release feature set, exactly as scripts/release-features.sh prints it")
    ap.add_argument("--workspace-a", default=".", help="first workspace (default: the current checkout)")
    ap.add_argument("--workspace-b", help="second workspace: created as a detached worktree of A's HEAD unless it exists")
    ap.add_argument("--bin", default="ai-memory", help="binary name under target/<target>/release/ (default ai-memory)")
    ap.add_argument("--epoch", help="SOURCE_DATE_EPOCH for both builds (default: A's HEAD committer timestamp)")
    ap.add_argument("--cargo", default="cargo", help="build tool to run (default cargo)")
    ap.add_argument("--sha256-output", help="append `sha256=<digest>` here when the two builds match "
                    "(the job's GITHUB_OUTPUT, #6274)")
    ap.add_argument("--nfpm", help="nfpm binary: also build and compare the deb and rpm of each workspace (#6283)")
    ap.add_argument("--nfpm-arch", help="ARCH for nfpm.yaml (with --nfpm)")
    ap.add_argument("--version", help="VERSION for nfpm.yaml (with --nfpm)")
    ap.add_argument("--pack", help="write a deterministic tarball of NAMEs here and print its SHA-256 (#6282)")
    ap.add_argument("--pack-root", default=".", help="directory the NAMEs are relative to (with --pack; default .)")
    ap.add_argument("names", nargs="*", help="files or directories to pack (with --pack)")
    ap.add_argument("--sha256", metavar="FILE", help="print the SHA-256 of one read of the regular file FILE (#6907)")
    ap.add_argument("--pack-binary", metavar="SRC", help="with --pack, --expect-sha256, --copy-to and --epoch: read SRC "
                    "once, refuse it unless its SHA-256 is the expected one, pack it and copy it (#6907)")
    ap.add_argument("--copy-to", metavar="DST", help="where --pack-binary writes the checked bytes (#6907)")
    ap.add_argument("--expect-sha256", metavar="HEX", help="the digest the strict assert recorded (#6907)")
    ap.add_argument("--verify-payload", action="store_true", help="check that each PACKAGE (deb or rpm) holds only "
                    "usr/bin/ai-memory with the --expect-sha256 digest (#6907)")
    ap.add_argument("--verify-dist", metavar="DIR", help="with --tarball and --expect-sha256: require DIR to hold "
                    "exactly the checked tarball, deb and rpm and one .sha256 sidecar each (#7018)")
    ap.add_argument("--tarball", metavar="NAME", help="the tarball --verify-dist expects in DIR (#7018)")
    ap.add_argument("--self-test", action="store_true", help="prove the comparison with a stub build tool")
    args = ap.parse_args(argv)
    root = Path(__file__).resolve().parent.parent.parent
    if args.self_test:
        return self_test(root)
    try:
        if args.sha256:
            if args.names or args.pack or args.pack_binary or args.verify_payload or args.verify_dist:
                ap.error("--sha256 takes exactly one FILE and no other mode")
            print(hashlib.sha256(read_once(Path(args.sha256))).hexdigest())
            return 0
        if args.verify_dist:
            if args.names or args.pack or args.pack_binary or args.verify_payload or not args.tarball:
                ap.error("--verify-dist takes DIR, --tarball and --expect-sha256 only")
            done = verify_dist(Path(args.verify_dist), args.tarball, args.expect_sha256)
            print(f"verified {args.verify_dist}: {done}, each with its .sha256, only the asserted binary")
            return 0
        if args.tarball:
            ap.error("--tarball is only accepted with --verify-dist")
        if args.verify_payload:
            if args.pack or args.pack_binary:
                ap.error("--verify-payload takes PACKAGEs and --expect-sha256 only")
            verify_payload([Path(n) for n in args.names], args.expect_sha256)
            print(f"verified {len(args.names)} package(s): only {PACKAGED_PATH} with the asserted SHA-256")
            return 0
        if args.pack_binary:
            if args.names or not args.pack or not args.copy_to or args.epoch is None:
                ap.error("--pack-binary needs --pack, --copy-to, --expect-sha256 and --epoch, and no NAMEs")
            print(pack_binary(Path(args.pack_binary), args.expect_sha256, Path(args.copy_to), Path(args.pack),
                              args.epoch))
            return 0
    except ProofError as exc:
        print(f"::error::reproducible-build: {exc}", file=sys.stderr)
        return 2
    if args.copy_to or args.expect_sha256:
        ap.error("--copy-to and --expect-sha256 are only accepted with --pack-binary or --verify-payload")
    if args.pack:
        if args.epoch is None:
            ap.error("--pack needs --epoch")
        try:
            print(pack_tarball(Path(args.pack), Path(args.pack_root), args.names, args.epoch))
        except ProofError as exc:
            print(f"::error::reproducible-build: {exc}", file=sys.stderr)
            return 2
        return 0
    if args.names:
        ap.error("NAMEs are only accepted with --pack")
    if not args.target or args.features is None or not args.workspace_b:
        ap.error("--target, --features and --workspace-b are required")
    try:
        return two_builds(Path(args.workspace_a).resolve(), Path(args.workspace_b).resolve(), args.target, args.features,
                          args.bin, args.cargo, epoch=args.epoch,
                          sha256_output=Path(args.sha256_output) if args.sha256_output else None,
                          nfpm=args.nfpm, nfpm_arch=args.nfpm_arch, version=args.version)
    except ProofError as exc:
        print(f"::error::reproducible-build: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
