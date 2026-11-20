#!/usr/bin/env python3
"""Stage and verify the HuggingFace model cache for CI (#9509).

One implementation for every workflow that needs the offline model cache (the
ci.yml `check` and `sal-feature` jobs and the coverage.yml
`per-module-thresholds` job). The step either leaves a cache whose every byte
matches the pinned manifest, or ends here with its own named error and exit
code before any test runs.

Layout the Rust loaders (`Embedder::load_from_fallback`,
`CrossEncoder::load_cross_encoder_from_fallback`, hf-hub `Cache::get`) read:
`<hub>/models--<org>--<name>/refs/main` holds a commit id, and
`<hub>/models--<org>--<name>/snapshots/<commit>/` holds config.json,
tokenizer.json and model.safetensors (each a regular file, or a symlink into
`blobs/`). `<hub>` is `$HF_HOME/hub`.

Pinned and fail closed (3-agent vote 71472661, D1-1 .. D1-4):
- each model has ONE revision constant (EMBEDDER_REVISION, RERANKER_REVISION);
  the fetch requests that revision, never `main`, and both workflow cache keys
  carry it (a census cell pins that);
- exit 0 needs refs/main to byte-equal the pinned revision, the leaf
  snapshots/<revision>/ to exist, and every artifact of MANIFEST to resolve
  inside the repo's own blobs/ or snapshots/ tree to a regular file with the
  pinned size and sha256 (the digest is taken over the resolved blob bytes);
  a fallback leaf (snapshots/main, another commit) never passes;
- the digest read copies scripts/ci/ensure-age-extension.py
  (`sha256_of_regular_file`: O_NOFOLLOW, S_ISREG, chunked sha256).

Job-private cache (D2-1): `--runner-temp` and `--workspace` name the runner's
temp dir and the checkout; the hub must be exactly
`<runner-temp>/<PRIVATE_DIR_NAME>/hub` (set by scripts/ci/hf_home_private.py
through $GITHUB_ENV) and outside the checkout, else exit EXIT_PLACEMENT, so a
self-hosted leg never reads or writes the runner user's real model cache.

The fetch is the standard library's urllib over https only: no child process,
no package install, no token read and no Authorization header, so neither a
token nor child output can reach the log (N7, N8).

Exit codes:
  0   every requested model matches the pinned manifest
  2   usage error (argparse)
  10  the cache does not match the pinned manifest (EXIT_LAYOUT)
  11  fetch failed after FETCH_ATTEMPTS attempts (EXIT_FETCH)
  13  the hub is not the job-private root (EXIT_PLACEMENT)

Output carries repo ids, relative names, the pinned revision and digits only,
never a host path, so a hostile HOME or ref cannot reach the log.

Python 3.12 floor, standard library only.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import re
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

EXIT_OK = 0
EXIT_LAYOUT = 10
EXIT_FETCH = 11
EXIT_PLACEMENT = 13

FETCH_ATTEMPTS = 5
BACKOFF_STEP_SECONDS = 10
FETCH_TIMEOUT_SECONDS = 900
READ_CHUNK_BYTES = 1 << 20

EMBEDDER_REPO = "sentence-transformers/all-MiniLM-L6-v2"
RERANKER_REPO = "cross-encoder/ms-marco-MiniLM-L-6-v2"
# The ONE source of each pinned revision (D1-4): the fetch, refs/main and both
# workflow cache keys use these values.
EMBEDDER_REVISION = "1110a243fdf4706b3f48f1d95db1a4f5529b4d41"
RERANKER_REVISION = "233902d25c440f23af6f7d6e94d2946bac0bee0a"
REVISIONS: dict[str, str] = {EMBEDDER_REPO: EMBEDDER_REVISION, RERANKER_REPO: RERANKER_REVISION}
MODEL_SETS: dict[str, tuple[str, ...]] = {
    "embedder": (EMBEDDER_REPO,),
    "all": (EMBEDDER_REPO, RERANKER_REPO),
}
# Mirrors HF_{CONFIG,TOKENIZER,WEIGHTS}_FILE in src/embeddings.rs.
CONFIG_FILE = "config.json"
TOKENIZER_FILE = "tokenizer.json"
WEIGHTS_FILE = "model.safetensors"
ARTIFACT_FILES = (CONFIG_FILE, TOKENIZER_FILE, WEIGHTS_FILE)

EMBEDDER_CONFIG_SIZE = 612
EMBEDDER_CONFIG_SHA256 = "953f9c0d463486b10a6871cc2fd59f223b2c70184f49815e7efbcab5d8908b41"
EMBEDDER_TOKENIZER_SIZE = 466247
EMBEDDER_TOKENIZER_SHA256 = "be50c3628f2bf5bb5e3a7f17b1f74611b2561a3a27eeab05e5aa30f411572037"
EMBEDDER_WEIGHTS_SIZE = 90868376
EMBEDDER_WEIGHTS_SHA256 = "53aa51172d142c89d9012cce15ae4d6cc0ca6895895114379cacb4fab128d9db"
RERANKER_CONFIG_SIZE = 794
RERANKER_CONFIG_SHA256 = "380e02c93f431831be65d99a4e7e5f67c133985bf2e77d9d4eba46847190bacc"
RERANKER_TOKENIZER_SIZE = 711396
RERANKER_TOKENIZER_SHA256 = "d241a60d5e8f04cc1b2b3e9ef7a4921b27bf526d9f6050ab90f9267a1f9e5c66"
RERANKER_WEIGHTS_SIZE = 90870598
RERANKER_WEIGHTS_SHA256 = "821d1aa69520101d6e0737f78a042ae25b19e5cb9160701909d10434f4aeb0ae"

# One tuple per artifact (D1-3, the ensure-age-extension.py MANIFEST shape):
# (repo, file name, size in bytes, sha256 of the blob bytes).
MANIFEST: tuple[tuple[str, str, int, str], ...] = (
    (EMBEDDER_REPO, CONFIG_FILE, EMBEDDER_CONFIG_SIZE, EMBEDDER_CONFIG_SHA256),
    (EMBEDDER_REPO, TOKENIZER_FILE, EMBEDDER_TOKENIZER_SIZE, EMBEDDER_TOKENIZER_SHA256),
    (EMBEDDER_REPO, WEIGHTS_FILE, EMBEDDER_WEIGHTS_SIZE, EMBEDDER_WEIGHTS_SHA256),
    (RERANKER_REPO, CONFIG_FILE, RERANKER_CONFIG_SIZE, RERANKER_CONFIG_SHA256),
    (RERANKER_REPO, TOKENIZER_FILE, RERANKER_TOKENIZER_SIZE, RERANKER_TOKENIZER_SHA256),
    (RERANKER_REPO, WEIGHTS_FILE, RERANKER_WEIGHTS_SIZE, RERANKER_WEIGHTS_SHA256),
)

# The job-private HF_HOME directory under runner.temp; scripts/ci/hf_home_private.py
# creates it and a census cell pins the two constants equal.
PRIVATE_DIR_NAME = "ai-memory-hf-home"
HUB_DIR_NAME = "hub"
HF_HOME_ENV = "HF_HOME"

HF_BASE_URL = "https://huggingface.co"
HTTPS_SCHEME = "https"
USER_AGENT = "ai-memory-ci-stage-hf-cache/9509"
REF_NAME = "main"
# A pinned ref is 40 hex bytes; anything longer is refused before it is decoded.
REF_MAX_BYTES = 64
# The reason words read_ref returns for a ref it cannot use (each is its own line).
REF_MISSING = "missing"
REF_UNREADABLE = "unreadable"
REF_NOT_REGULAR = "not a regular file"
INCOMPLETE_SUFFIX = ".incomplete"
BLOB_MODE = 0o644
UNSAFE_CHARS_RE = re.compile(r"[^A-Za-z0-9._/ ()=-]")
MAX_MESSAGE_CHARS = 300


def clean(text: str) -> str:
    """Keep only characters that can never start, end or alter a workflow command.

    Every message is built from repo ids, relative file names, the pinned revision and
    digits, so the alphabet is closed: no colon pair, percent, hash, bracket or line break
    survives, whatever a hostile HOME or ref puts in a name (#9365).
    """
    return UNSAFE_CHARS_RE.sub("?", text)[:MAX_MESSAGE_CHARS]


def error(text: str) -> None:
    print("::error::stage_hf_cache:", clean(text))


def notice(text: str) -> None:
    print("::notice::stage_hf_cache:", clean(text))


def warning(text: str) -> None:
    print("::warning::stage_hf_cache:", clean(text))


def hub_root(env: Mapping[str, str]) -> Path | None:
    """`$HF_HOME/hub`; None when HF_HOME is unset or blank (the job-private root is required)."""
    hf_home = env.get(HF_HOME_ENV, "")
    if not hf_home.strip():
        return None
    return Path(hf_home) / HUB_DIR_NAME


def repo_dir(hub: Path, repo: str) -> Path:
    return hub / ("models--" + repo.replace("/", "--"))


def artifacts_of(repo: str, manifest: Sequence[tuple[str, str, int, str]]) -> list[tuple[str, int, str]]:
    return [(name, size, digest) for owner, name, size, digest in manifest if owner == repo]


def sha256_of_regular_file(path, refuse_writable=False):
    """sha256 of path when it is a regular file (not a symlink), else None.

    Copied from scripts/ci/ensure-age-extension.py (D1-3: one digest idiom).
    With refuse_writable, a group- or world-writable file also gives None (#7016).
    """
    try:
        fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return None
    try:
        mode = os.fstat(fd).st_mode
        if not stat.S_ISREG(mode) or (refuse_writable and mode & (stat.S_IWGRP | stat.S_IWOTH)):
            return None
        digest = hashlib.sha256()
        with os.fdopen(fd, "rb", closefd=False) as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None
    finally:
        os.close(fd)


def read_ref(path: Path) -> tuple[bytes | None, str]:
    """(bytes, "") of a regular, non-symlink ref file (at most REF_MAX_BYTES + 1 bytes read),
    else (None, the reason word: REF_MISSING, REF_NOT_REGULAR or REF_UNREADABLE)."""
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return None, REF_MISSING
    except OSError:
        return None, REF_UNREADABLE
    if not stat.S_ISREG(info.st_mode):
        return None, REF_NOT_REGULAR
    try:
        fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None, REF_MISSING
    except OSError:
        return None, REF_UNREADABLE
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None, REF_NOT_REGULAR
        with os.fdopen(fd, "rb", closefd=False) as fh:
            return fh.read(REF_MAX_BYTES + 1), ""
    except OSError:
        return None, REF_UNREADABLE
    finally:
        os.close(fd)


def is_real_dir(path: Path) -> bool:
    try:
        return stat.S_ISDIR(os.lstat(path).st_mode)
    except OSError:
        return False


def inside(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip(os.sep) + os.sep)


def artifact_problem(base: Path, snap: Path, rel: str, name: str, size: int, digest: str) -> str | None:
    """Why snapshots/<rev>/<name> does not resolve to the pinned blob, or None."""
    entry = snap / name
    where = f"{name} in {rel}"
    try:
        info = os.lstat(entry)
    except FileNotFoundError:
        return f"missing {where}"
    except OSError:
        return f"unreadable {where}"
    if stat.S_ISLNK(info.st_mode):
        resolved = os.path.realpath(entry)
        real_base = os.path.realpath(base)
        allowed = (os.path.join(real_base, "blobs"), os.path.join(real_base, "snapshots"))
        if not any(inside(resolved, root) for root in allowed):
            return f"{where} resolves outside the repo cache"
        target = Path(resolved)
    elif stat.S_ISREG(info.st_mode):
        target = entry
    else:
        return f"{where} is not a regular file"
    try:
        real = os.lstat(target)
    except FileNotFoundError:
        return f"missing {where} (dangling link)"
    except OSError:
        return f"unreadable {where}"
    if not stat.S_ISREG(real.st_mode):
        return f"{where} is not a regular file"
    if real.st_size != size:
        return f"{where} has {real.st_size} bytes, pinned {size}"
    got = sha256_of_regular_file(target)
    if got is None:
        return f"unreadable {where}"
    if got != digest:
        return f"{where} sha256 differs from the pinned digest"
    return None


def repo_problems(
    hub: Path, repo: str, revision: str, manifest: Sequence[tuple[str, str, int, str]] = MANIFEST
) -> list[str]:
    """The reasons `repo` does not match the pinned manifest under `hub` (empty = ok)."""
    base = repo_dir(hub, repo)
    data, reason = read_ref(base / "refs" / REF_NAME)
    if data is None:
        if reason == REF_NOT_REGULAR:
            return [f"ref refs/{REF_NAME} for {repo} is not a regular file"]
        return [f"{reason} ref refs/{REF_NAME} for {repo}"]
    try:
        data.decode("ascii", "strict")
    except UnicodeDecodeError:
        return [f"undecodable ref refs/{REF_NAME} for {repo} (not ASCII)"]
    if data != revision.encode("ascii"):
        return [f"ref refs/{REF_NAME} for {repo} is not the pinned revision {revision}"]
    rel = f"snapshots/{revision}"
    snap = base / "snapshots" / revision
    if not is_real_dir(snap):
        return [f"missing snapshot dir {rel} for {repo}"]
    problems = []
    for name, size, digest in artifacts_of(repo, manifest):
        problem = artifact_problem(base, snap, rel, name, size, digest)
        if problem is not None:
            problems.append(f"{problem} for {repo}")
    return problems


class HttpsOnlyRedirect(urllib.request.HTTPRedirectHandler):
    """Follow a redirect only to another https URL (the LFS CDN); anything else is a failed attempt."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urllib.parse.urlsplit(newurl).scheme != HTTPS_SCHEME:
            raise urllib.error.HTTPError(newurl, code, "redirect to a non-https URL refused", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def artifact_url(repo: str, revision: str, name: str) -> str:
    return f"{HF_BASE_URL}/{repo}/resolve/{revision}/{name}"


def open_url(url: str) -> BinaryIO:
    """GET `url` over https with no credentials: no token is read and no Authorization header is sent."""
    if urllib.parse.urlsplit(url).scheme != HTTPS_SCHEME:
        raise urllib.error.URLError("non-https URL refused")
    opener = urllib.request.build_opener(HttpsOnlyRedirect())
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    return opener.open(request, timeout=FETCH_TIMEOUT_SECONDS)


@dataclass
class Ops:
    """Side effects, injected so the cells never touch the network or sleep."""

    open_url: Callable[[str], BinaryIO]
    sleep: Callable[[int], None]


def real_ops() -> Ops:
    return Ops(open_url=open_url, sleep=time.sleep)


def ensure_real_dir(path: Path) -> None:
    """mkdir -p that refuses a symlinked or non-directory component inside the repo tree."""
    path.mkdir(parents=True, exist_ok=True)
    if not is_real_dir(path):
        raise OSError(f"{path.name} is not a real directory")


def download_blob(ops: Ops, url: str, blobs: Path, size: int, digest: str) -> bool:
    """Write the pinned blob to blobs/<sha256>, hashing while writing; True only on an exact match."""
    final = blobs / digest
    partial = blobs / (digest + INCOMPLETE_SUFFIX)
    hasher = hashlib.sha256()
    written = 0
    fd = os.open(str(partial), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, BLOB_MODE)
    try:
        with os.fdopen(fd, "wb", closefd=False) as out, ops.open_url(url) as resp:
            while True:
                chunk = resp.read(min(READ_CHUNK_BYTES, size + 1 - written))
                if not chunk:
                    break
                written += len(chunk)
                if written > size:
                    break
                hasher.update(chunk)
                out.write(chunk)
    finally:
        os.close(fd)
    if written != size or hasher.hexdigest() != digest:
        partial.unlink(missing_ok=True)
        return False
    os.replace(partial, final)
    return True


def replace_link(link: Path, target: str) -> None:
    """Point `link` at `target`, replacing whatever entry was there (never following it)."""
    tmp = link.with_name(link.name + INCOMPLETE_SUFFIX)
    tmp.unlink(missing_ok=True)
    os.symlink(target, tmp)
    os.replace(tmp, link)


def write_ref(ref: Path, revision: str) -> None:
    tmp = ref.with_name(ref.name + INCOMPLETE_SUFFIX)
    tmp.unlink(missing_ok=True)
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, BLOB_MODE)
    with os.fdopen(fd, "wb") as out:
        out.write(revision.encode("ascii"))
    os.replace(tmp, ref)


def fetch_repo(
    hub: Path, repo: str, revision: str, ops: Ops, manifest: Sequence[tuple[str, str, int, str]]
) -> bool:
    """Fetch every artifact of `repo` at the pinned revision; refs/main is written last."""
    base = repo_dir(hub, repo)
    blobs = base / "blobs"
    snap = base / "snapshots" / revision
    for path in (hub, base, blobs, base / "snapshots", snap, base / "refs"):
        ensure_real_dir(path)
    for name, size, digest in artifacts_of(repo, manifest):
        if sha256_of_regular_file(blobs / digest) != digest and not download_blob(
            ops, artifact_url(repo, revision, name), blobs, size, digest
        ):
            return False
        replace_link(snap / name, os.path.join("..", "..", "blobs", digest))
    write_ref(base / "refs" / REF_NAME, revision)
    return True


def fetch_with_retry(
    hub: Path, repo: str, revision: str, ops: Ops, manifest: Sequence[tuple[str, str, int, str]]
) -> bool:
    for attempt in range(1, FETCH_ATTEMPTS + 1):
        try:
            ok = fetch_repo(hub, repo, revision, ops, manifest)
        except (OSError, ValueError):  # urllib.error.URLError and HTTPError are OSError
            ok = False
        if ok:
            notice(f"staged {repo} at {revision} (attempt {attempt})")
            return True
        warning(f"fetch {repo} attempt {attempt} failed")
        if attempt < FETCH_ATTEMPTS:
            ops.sleep(attempt * BACKOFF_STEP_SECONDS)
    return False


def placement_problem(hub: Path | None, runner_temp: str, workspace: str) -> str | None:
    """Why the hub is not `<runner-temp>/<PRIVATE_DIR_NAME>/hub` outside the checkout, or None."""
    if hub is None:
        return f"{HF_HOME_ENV} is not set; run scripts/ci/hf_home_private.py first"
    if not os.path.isabs(runner_temp) or not os.path.isabs(workspace):
        return "runner temp and workspace must be absolute paths"
    real_hub = os.path.realpath(hub)
    want = os.path.join(os.path.realpath(runner_temp), PRIVATE_DIR_NAME, HUB_DIR_NAME)
    if real_hub != want:
        return f"{HF_HOME_ENV} is not the job-private root under the runner temp dir"
    real_workspace = os.path.realpath(workspace)
    if inside(real_hub, real_workspace) or inside(real_workspace, os.path.dirname(real_hub)):
        return f"{HF_HOME_ENV} overlaps the checkout"
    return None


def stage(
    hub: Path,
    repos: Sequence[str],
    ops: Ops,
    verify_only: bool,
    manifest: Sequence[tuple[str, str, int, str]] = MANIFEST,
) -> int:
    if not verify_only:
        for repo in repos:
            if repo_problems(hub, repo, REVISIONS[repo], manifest) and not fetch_with_retry(
                hub, repo, REVISIONS[repo], ops, manifest
            ):
                error(f"could not stage {repo} after {FETCH_ATTEMPTS} attempts")
                return EXIT_FETCH
    failed = False
    for repo in repos:
        problems = repo_problems(hub, repo, REVISIONS[repo], manifest)
        for problem in problems:
            error(problem)
        failed = failed or bool(problems)
        if not problems:
            notice(f"{repo} matches the pinned manifest at {REVISIONS[repo]}")
    return EXIT_LAYOUT if failed else EXIT_OK


def main(
    argv: Sequence[str] | None = None,
    ops: Ops | None = None,
    env: Mapping[str, str] | None = None,
) -> int:
    parser = argparse.ArgumentParser(description="Stage and verify the pinned HuggingFace model cache (#9509).")
    parser.add_argument("--models", choices=sorted(MODEL_SETS), required=True)
    parser.add_argument("--runner-temp", required=True, help="the runner temp dir (runner.temp)")
    parser.add_argument("--workspace", required=True, help="the checkout (github.workspace)")
    parser.add_argument("--verify-only", action="store_true", help="check the cache; never fetch")
    args = parser.parse_args(argv)
    env = os.environ if env is None else env
    hub = hub_root(env)
    problem = placement_problem(hub, args.runner_temp, args.workspace)
    if problem is not None or hub is None:
        error(problem or f"{HF_HOME_ENV} is not set")
        return EXIT_PLACEMENT
    return stage(hub, MODEL_SETS[args.models], ops or real_ops(), args.verify_only)


if __name__ == "__main__":
    sys.exit(main())
