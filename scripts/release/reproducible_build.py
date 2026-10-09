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

Workspace B is a detached ``git worktree`` of workspace A's HEAD unless the
directory already exists (then it is used as is: that is how ``--self-test``
and a caller with its own second checkout drive it). No build cache is shared
or restored: the point is two independent builds.

On a mismatch the script prints both digests, both sizes, the number of
differing bytes and the first differing offset, the ELF section table of each
binary (``readelf -S``, when present) and a ``diffoscope`` report (when
installed), then exits 1. A build that fails, a binary that is missing, or a
git / worktree error exits 2. Only an exact digest match exits 0.

``--self-test`` drives the comparison with a stub ``cargo`` that writes a
binary derived from SOURCE_DATE_EPOCH, the feature set, the target and the
REMAPPED working directory: two builds must match; a perturbed epoch on the
second build and an unremapped workspace path must each be reported as a
mismatch (the negative fixtures #3613 asks for).

Usage:
  scripts/release/reproducible_build.py --target T --features F --workspace-b DIR
      [--workspace-a DIR] [--bin NAME] [--epoch N] [--cargo PATH]
  scripts/release/reproducible_build.py --self-test
Exit codes: 0 identical · 1 mismatch · 2 usage, build or git error.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import List, Optional, Tuple

REMAP_SRC = "/src"
REMAP_CARGO = "/cargo"
CHUNK = 1 << 20


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
    """One release build in ``workspace``; returns the built binary's path."""
    env = dict(os.environ)
    env["SOURCE_DATE_EPOCH"] = epoch
    env["RUSTFLAGS"] = rustflags_for(workspace, remap)
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
    """Workspace B is a detached worktree of A's HEAD unless it already exists."""
    if workspace_b.exists():
        return
    workspace_b.parent.mkdir(parents=True, exist_ok=True)
    git(workspace_a, "worktree", "add", "--detach", str(workspace_b), "HEAD")


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
               epoch: Optional[str] = None, epoch_b: Optional[str] = None, remap: bool = True) -> int:
    """Build in both workspaces and compare. Returns the exit code (0 / 1).
    ``epoch_b`` and ``remap=False`` exist for the negative fixtures only."""
    if not features.strip():
        raise ProofError("--features is empty (the release feature declaration came back empty: fail closed)")
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
    print(f"reproducible-build: OK (two builds of {bin_name} for {target} are byte-identical: {sha_a})", flush=True)
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
out = pathlib.Path("target") / target / "release" / "ai-memory"
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text("epoch=%s features=%s target=%s cwd=%s\\n" % (os.environ.get("SOURCE_DATE_EPOCH"), features, target, cwd))
'''


def self_test(root: Path) -> int:
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

        def fresh() -> None:
            for ws in (ws_a, ws_b):
                shutil.rmtree(ws, ignore_errors=True)
                ws.mkdir()

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
    for f in failures:
        print(f"reproducible_build: self-test FAIL: {f}", file=sys.stderr)
    if failures:
        return 1
    print("reproducible_build: self-test OK (identical builds pass; perturbed epoch, unremapped path, empty feature set "
          "and missing build tool are refused)")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Two-build byte-identity proof of a release binary (#3613).")
    ap.add_argument("--target", help="cargo --target triple (the release matrix leg being proven)")
    ap.add_argument("--features", help="the release feature set, exactly as scripts/release-features.sh prints it")
    ap.add_argument("--workspace-a", default=".", help="first workspace (default: the current checkout)")
    ap.add_argument("--workspace-b", help="second workspace: created as a detached worktree of A's HEAD unless it exists")
    ap.add_argument("--bin", default="ai-memory", help="binary name under target/<target>/release/ (default ai-memory)")
    ap.add_argument("--epoch", help="SOURCE_DATE_EPOCH for both builds (default: A's HEAD committer timestamp)")
    ap.add_argument("--cargo", default="cargo", help="build tool to run (default cargo)")
    ap.add_argument("--self-test", action="store_true", help="prove the comparison with a stub build tool")
    args = ap.parse_args(argv)
    root = Path(__file__).resolve().parent.parent.parent
    if args.self_test:
        return self_test(root)
    if not args.target or args.features is None or not args.workspace_b:
        ap.error("--target, --features and --workspace-b are required")
    try:
        return two_builds(Path(args.workspace_a).resolve(), Path(args.workspace_b).resolve(), args.target, args.features,
                          args.bin, args.cargo, epoch=args.epoch)
    except ProofError as exc:
        print(f"::error::reproducible-build: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
