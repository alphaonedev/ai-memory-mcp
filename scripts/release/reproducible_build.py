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
  scripts/release/reproducible_build.py --self-test
Exit codes: 0 identical · 1 mismatch · 2 usage, build or git error.
"""
from __future__ import annotations

import argparse
import hashlib
import gzip
import os
import re
import shutil
import stat
import tarfile
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath
from typing import List, Optional, Tuple

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
    for f in failures:
        print(f"reproducible_build: self-test FAIL: {f}", file=sys.stderr)
    if failures:
        return 1
    print("reproducible_build: self-test OK (identical builds pass; perturbed epoch, unremapped path, empty feature set "
          "and missing build tool are refused; a stale, dirty or prebuilt workspace B, a compiler wrapper and caller "
          "environment leaks are refused, #6291; the packed tarball and the deb/rpm are compared and a "
          "perturbed packing epoch is refused, #6282/#6283)")
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
    ap.add_argument("--self-test", action="store_true", help="prove the comparison with a stub build tool")
    args = ap.parse_args(argv)
    root = Path(__file__).resolve().parent.parent.parent
    if args.self_test:
        return self_test(root)
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
