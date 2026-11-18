#!/usr/bin/env python3
"""Stage and verify the HuggingFace model cache for CI (#9509).

One implementation for every workflow that needs the offline embedder cache
(the ci.yml `check` job and the coverage.yml `per-module-thresholds` job). The
step either leaves a cache the Rust loader resolves, or ends here with its own
named error and exit code before any test runs.

Layout the Rust loaders (`Embedder::load_from_fallback`, hf-hub `Cache::get`)
read: `<hub>/models--<org>--<name>/refs/main` holds a commit id, and
`<hub>/models--<org>--<name>/snapshots/<commit>/` holds config.json,
tokenizer.json and model.safetensors. `<hub>` is `$HF_HOME/hub`, else
`$HOME/.cache/huggingface/hub`.

The model revision is not pinned: `snapshot_download(<repo>)` resolves the
default branch, exactly as the coverage.yml step did before it moved here.

Exit codes:
  0   every requested repo is resolvable
  2   usage error (argparse)
  10  layout check failed (a ref, snapshot or file is missing)
  11  fetch failed after FETCH_ATTEMPTS attempts
  12  huggingface_hub could not be installed

The script reads no secret and no token. Output carries repo ids and relative
names only, never the host paths, so a hostile HOME cannot reach the log.

Python 3.12 floor, standard library only.
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

EXIT_OK = 0
EXIT_LAYOUT = 10
EXIT_FETCH = 11
EXIT_INSTALL = 12

FETCH_ATTEMPTS = 5
BACKOFF_STEP_SECONDS = 10
FETCH_TIMEOUT_SECONDS = 900
INSTALL_TIMEOUT_SECONDS = 300

EMBEDDER_REPO = "sentence-transformers/all-MiniLM-L6-v2"
RERANKER_REPO = "cross-encoder/ms-marco-MiniLM-L-6-v2"
MODEL_SETS: dict[str, tuple[str, ...]] = {
    "embedder": (EMBEDDER_REPO,),
    "all": (EMBEDDER_REPO, RERANKER_REPO),
}
# Mirrors HF_{CONFIG,TOKENIZER,WEIGHTS}_FILE in src/embeddings.rs.
ARTIFACT_FILES = ("config.json", "tokenizer.json", "model.safetensors")

HUB_SPEC = "huggingface_hub>=0.20"
# The classic (non-Xet) cache is what the Rust hf-hub reads; the Xet CAS backend
# intermittently returned 401 (#2019b).
DISABLE_XET_ENV = "HF_HUB_DISABLE_XET"
# Env that would redirect or disable the fetch or the cache the loaders read.
FETCH_ENV_DROP = ("HF_HUB_CACHE", "HUGGINGFACE_HUB_CACHE", "HF_HUB_OFFLINE", "HF_TOKEN")
SNAPSHOT_CODE = "import sys; from huggingface_hub import snapshot_download; snapshot_download(sys.argv[1])"
COMMIT_RE = re.compile(r"[A-Za-z0-9._-]{1,128}")
UNSAFE_CHARS_RE = re.compile(r"[^A-Za-z0-9._/ ()=-]")
MAX_MESSAGE_CHARS = 300


def clean(text: str) -> str:
    """Keep only characters that can never start, end or alter a workflow command.

    Every message is built from repo ids, relative file names, a validated commit id and
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


def hub_root(env: Mapping[str, str]) -> Path:
    """Same order as `staged_model_snapshot_dir` in src/embeddings.rs."""
    hf_home = env.get("HF_HOME", "")
    if hf_home.strip():
        return Path(hf_home) / "hub"
    return Path(env.get("HOME", "/root")) / ".cache" / "huggingface" / "hub"


def layout_problems(hub: Path, repo: str) -> list[str]:
    """Return the reasons `repo` is not hf-hub-resolvable under `hub` (empty = ok)."""
    base = hub / ("models--" + repo.replace("/", "--"))
    ref = base / "refs" / "main"
    try:
        commit = ref.read_text().strip()
    except OSError:
        return [f"missing ref refs/main for {repo}"]
    if not COMMIT_RE.fullmatch(commit) or commit in (".", ".."):
        return [f"invalid ref content in refs/main for {repo}"]
    snap = base / "snapshots" / commit
    if not snap.is_dir():
        return [f"missing snapshot dir snapshots/{commit} for {repo}"]
    # exists() follows symlinks: hf cache snapshots are symlinks into blobs/.
    return [
        f"missing {name} in snapshots/{commit} for {repo}"
        for name in ARTIFACT_FILES
        if not (snap / name).exists()
    ]


@dataclass
class Ops:
    """Side effects, injected so the cells never touch the network or sleep."""

    fetch: Callable[[str], bool]
    install: Callable[[], bool]
    have_hub: Callable[[], bool]
    sleep: Callable[[int], None]


def fetch_env(env: Mapping[str, str], hub: Path) -> dict[str, str]:
    out = {k: v for k, v in env.items() if k not in FETCH_ENV_DROP}
    out["HF_HOME"] = str(hub.parent)
    out[DISABLE_XET_ENV] = "1"
    return out


def real_ops(env: Mapping[str, str], hub: Path) -> Ops:
    child_env = fetch_env(env, hub)

    def run(argv: list[str], timeout: int) -> bool:
        try:
            return subprocess.run(argv, env=child_env, timeout=timeout, check=False).returncode == 0
        except (subprocess.TimeoutExpired, OSError):
            return False

    def have_hub() -> bool:
        return run([sys.executable, "-c", "import huggingface_hub"], INSTALL_TIMEOUT_SECONDS)

    def install() -> bool:
        pip = [sys.executable, "-m", "pip", "install", "--quiet", "--disable-pip-version-check", HUB_SPEC]
        return run(pip, INSTALL_TIMEOUT_SECONDS) or run(
            ["pip3", "install", "--quiet", HUB_SPEC], INSTALL_TIMEOUT_SECONDS
        )

    def fetch(repo: str) -> bool:
        return run([sys.executable, "-c", SNAPSHOT_CODE, repo], FETCH_TIMEOUT_SECONDS)

    return Ops(fetch=fetch, install=install, have_hub=have_hub, sleep=time.sleep)


def fetch_with_retry(repo: str, ops: Ops) -> bool:
    for attempt in range(1, FETCH_ATTEMPTS + 1):
        try:
            ok = ops.fetch(repo)
        except (subprocess.TimeoutExpired, OSError):
            ok = False
        if ok:
            notice(f"staged {repo} (attempt {attempt})")
            return True
        warning(f"fetch {repo} attempt {attempt} failed")
        if attempt < FETCH_ATTEMPTS:
            ops.sleep(attempt * BACKOFF_STEP_SECONDS)
    return False


def stage(hub: Path, repos: Sequence[str], ops: Ops, verify_only: bool) -> int:
    missing = [r for r in repos if layout_problems(hub, r)]
    if missing and not verify_only:
        if not ops.have_hub() and not ops.install():
            error("could not install huggingface_hub")
            return EXIT_INSTALL
        for repo in missing:
            if not fetch_with_retry(repo, ops):
                error(f"could not stage {repo} after {FETCH_ATTEMPTS} attempts")
                return EXIT_FETCH
    failed = False
    for repo in repos:
        problems = layout_problems(hub, repo)
        for problem in problems:
            error(problem)
        failed = failed or bool(problems)
        if not problems:
            notice(f"{repo} resolvable ({len(ARTIFACT_FILES)} artifacts)")
    return EXIT_LAYOUT if failed else EXIT_OK


def main(
    argv: Sequence[str] | None = None,
    ops: Ops | None = None,
    env: Mapping[str, str] | None = None,
) -> int:
    parser = argparse.ArgumentParser(description="Stage and verify the HuggingFace model cache (#9509).")
    parser.add_argument("--models", choices=sorted(MODEL_SETS), required=True)
    parser.add_argument("--verify-only", action="store_true", help="check the layout; never fetch or install")
    args = parser.parse_args(argv)
    env = os.environ if env is None else env
    hub = hub_root(env)
    return stage(hub, MODEL_SETS[args.models], ops or real_ops(env, hub), args.verify_only)


if __name__ == "__main__":
    sys.exit(main())
