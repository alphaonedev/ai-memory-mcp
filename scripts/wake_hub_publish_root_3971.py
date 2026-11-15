#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""#3971 W-5: prove the wake-hub snapshot hand-off as REAL root across two uids.

The packaged refresher unit runs, as root,

    /usr/bin/env -i AI_MEMORY_NO_CONFIG=1 /usr/bin/ai-memory wake-hub \
        --publish-snapshot <staging file> --allowlist <hub file>

This script reproduces that on a disposable CI runner: two system users (the
unprivileged writer and the hub), a 0700 staging directory owned by the
writer and a 0700 hub directory owned by the hub. It proves:

* a valid snapshot is published owned by the hub uid at mode 0600, by a new
  inode, and the hub (running as its own uid) admits it;
* a symlink swapped in for the source, a symlinked staging directory, a
  hard-linked source, a FIFO held open by a writer that never writes, an
  over-size source, group-writable directories, a same-owner hand-off and a
  root-owned staging directory each publish NOTHING, exit 1 and name their
  reason, in bounded time;
* a polluted environment (config, database, log and key variables) changes
  neither the outcome nor the output.

It must run as root and is meant ONLY for a disposable CI VM. It refuses to
run otherwise. Standard library only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pwd
import shutil
import stat
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

WRITER = "aimem-stage-3971"
HUB = "aimem-hub-3971"
BASE = Path("/var/lib/aimem-publish-3971")
REFUSED = "wake-hub: --publish-snapshot refused:"
EXIT_PUBLISHED = 0
EXIT_REFUSED = 1
# Wall-clock ceiling for one publish call; a blocked read would blow it.
CALL_TIMEOUT_S = 15.0
REFUSAL_CEILING_S = 10.0
MAX_SNAPSHOT_BYTES = 1_048_576
# RFC 8032 test vector 1 public key: a valid Ed25519 point.
PUBKEY_B64 = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
ALLOWLIST_FILE_VERSION = 2


class CheckFailed(Exception):
    """One assertion of this proof did not hold."""


def check(cond: bool, what: str) -> None:
    if not cond:
        raise CheckFailed(what)
    print(f"PASS {what}")


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def snapshot_bytes() -> bytes:
    now = datetime.now(timezone.utc).isoformat()
    return json.dumps(
        {
            "version": ALLOWLIST_FILE_VERSION,
            "refreshed_at": now,
            "agents": [
                {
                    "agent_id": "ai:alice",
                    "pubkey_b64": PUBKEY_B64,
                    "bind_authority": "possession_proof",
                    "bound_at": now,
                    "revoked_keys": [],
                    "readable_prefixes": [],
                }
            ],
        }
    ).encode()


def ensure_user(name: str) -> pwd.struct_passwd:
    try:
        return pwd.getpwnam(name)
    except KeyError:
        subprocess.run(
            ["useradd", "--system", "--no-create-home", "--shell", "/usr/sbin/nologin", name],
            check=True,
        )
        return pwd.getpwnam(name)


def place(path: Path, data: bytes, owner: pwd.struct_passwd, mode: int = 0o600) -> None:
    """Write `data` at `path` owned by `owner` at `mode` (no follow)."""
    if path.is_symlink() or path.exists():
        path.unlink()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, data)
        os.fchown(fd, owner.pw_uid, owner.pw_gid)
        os.fchmod(fd, mode)
    finally:
        os.close(fd)


def mkdir_owned(path: Path, owner: pwd.struct_passwd, mode: int = 0o700) -> None:
    path.mkdir(exist_ok=True)
    os.chown(path, owner.pw_uid, owner.pw_gid)
    os.chmod(path, mode)


def publish(
    binary: Path, src: Path, dest: Path, env: dict[str, str] | None = None
) -> tuple[int, str, str, float]:
    if env is None:
        argv = ["/usr/bin/env", "-i", "AI_MEMORY_NO_CONFIG=1", str(binary)]
        run_env: dict[str, str] = {}
    else:
        argv = [str(binary)]
        run_env = env
    argv += ["wake-hub", "--publish-snapshot", str(src), "--allowlist", str(dest)]
    start = time.monotonic()
    proc = subprocess.run(
        argv, env=run_env, capture_output=True, text=True, timeout=CALL_TIMEOUT_S, check=False
    )
    return proc.returncode, proc.stdout.strip(), proc.stderr.strip(), time.monotonic() - start


def expect_refused(
    binary: Path, src: Path, dest: Path, reason: str, row: str
) -> None:
    before = sha(dest)
    entries = sorted(p.name for p in dest.parent.iterdir())
    rc, out, err, took = publish(binary, src, dest)
    check(rc == EXIT_REFUSED, f"{row}: exit {EXIT_REFUSED} (got {rc}: {err})")
    check(err == f"{REFUSED} {reason}", f"{row}: exact reason (got {err!r})")
    check(out == "", f"{row}: no report on stdout")
    check(took < REFUSAL_CEILING_S, f"{row}: refused in {took:.2f}s")
    check(sha(dest) == before, f"{row}: destination byte-unchanged")
    check(
        sorted(p.name for p in dest.parent.iterdir()) == entries,
        f"{row}: no temp file left in the hub directory",
    )


def run(binary: Path) -> None:
    writer = ensure_user(WRITER)
    hub = ensure_user(HUB)
    root = pwd.getpwuid(0)
    if BASE.exists():
        shutil.rmtree(BASE)
    BASE.mkdir(mode=0o755)
    stage = BASE / "stage"
    hubdir = BASE / "hub"
    mkdir_owned(stage, writer)
    mkdir_owned(hubdir, hub)
    src = stage / "hub-allow.json"
    dest = hubdir / "hub-allow.json"

    # 1. The success path, exactly as the unit runs it.
    place(src, snapshot_bytes(), writer)
    rc, out, err, _ = publish(binary, src, dest)
    check(rc == EXIT_PUBLISHED, f"publish exits 0 (got {rc}: {err})")
    st = os.lstat(dest)
    check(stat.S_ISREG(st.st_mode), "published file is a regular file")
    check((st.st_uid, st.st_gid) == (hub.pw_uid, hub.pw_gid), "published file owned by the hub uid")
    check(stat.S_IMODE(st.st_mode) == 0o600, "published file mode 0600")
    check(st.st_nlink == 1, "published file has one link")
    check(len(json.loads(dest.read_bytes())["agents"]) == 1, "published snapshot carries the agent")
    check(sorted(p.name for p in hubdir.iterdir()) == ["hub-allow.json"], "no temp file left")
    clean_out = out

    # The hub, as its own uid, admits the published snapshot.
    posture = subprocess.run(
        ["runuser", "-u", HUB, "--", "/usr/bin/env", "-i", "AI_MEMORY_NO_CONFIG=1", str(binary),
         "wake-hub", "--socket", str(hubdir / "hub.sock"), "--allowlist", str(dest),
         "--posture", "--require-admits"],
        capture_output=True, text=True, timeout=CALL_TIMEOUT_S, check=False,
    )
    check(posture.returncode == 0, f"the hub admits the published snapshot (rc {posture.returncode}: {posture.stderr.strip()})")

    # A second publish replaces by a NEW inode (atomic rename).
    old_ino = st.st_ino
    place(src, snapshot_bytes(), writer)
    rc, _, err, _ = publish(binary, src, dest)
    check(rc == EXIT_PUBLISHED, f"republish exits 0 (got {rc}: {err})")
    check(os.lstat(dest).st_ino != old_ino, "republish renames a new inode into place")

    # 2. Every refusal publishes nothing.
    secret = stage / "secret"
    place(secret, b"root-only bytes", root)
    src.unlink()
    os.symlink("/etc/shadow", src)
    os.lchown(src, writer.pw_uid, writer.pw_gid)
    expect_refused(binary, src, dest, f"source {src} is a symlink", "symlink swap to /etc/shadow")
    secret.unlink()
    src.unlink()

    link = BASE / "stage-link"
    os.symlink(stage, link)
    place(src, snapshot_bytes(), writer)
    expect_refused(
        binary, link / "hub-allow.json", dest,
        f"directory {link} is reached through a symlink", "symlinked staging directory",
    )
    link.unlink()

    other = stage / "other"
    place(other, snapshot_bytes(), writer)
    src.unlink()
    os.link(other, src)
    expect_refused(binary, src, dest, f"source {src} has 2 hard links; exactly 1 is required", "hard link")
    src.unlink()
    other.unlink()

    os.mkfifo(src, 0o600)
    os.chown(src, writer.pw_uid, writer.pw_gid)
    held = os.open(src, os.O_RDWR | os.O_NONBLOCK)  # a writer that never writes
    try:
        expect_refused(binary, src, dest, f"source {src} is not a regular file", "stalled FIFO")
    finally:
        os.close(held)
    src.unlink()

    big = 4 * MAX_SNAPSHOT_BYTES
    place(src, b" " * big, writer)
    expect_refused(
        binary, src, dest,
        f"source {src} is {big} bytes, over the {MAX_SNAPSHOT_BYTES} byte ceiling", "over-size",
    )

    place(src, snapshot_bytes(), writer, 0o644)
    expect_refused(binary, src, dest, f"source {src} must be mode 0600, found 0644", "wrong mode")

    place(src, snapshot_bytes(), hub)
    expect_refused(
        binary, src, dest,
        f"source {src} is owned by uid {hub.pw_uid}, not by its directory's owner (uid {writer.pw_uid})",
        "foreign-owned source",
    )

    place(src, snapshot_bytes(), writer)
    os.chmod(stage, 0o770)
    expect_refused(
        binary, src, dest,
        f"source directory {stage} is group- or world-writable (mode 0770)", "group-writable stage",
    )
    os.chmod(stage, 0o700)
    os.chmod(hubdir, 0o770)
    expect_refused(
        binary, src, dest,
        f"destination directory {hubdir} is group- or world-writable (mode 0770)", "group-writable hub",
    )
    os.chmod(hubdir, 0o700)

    os.chown(hubdir, writer.pw_uid, writer.pw_gid)
    expect_refused(
        binary, src, dest,
        f"destination directory {hubdir} has the same owner (uid {writer.pw_uid}) as the source directory; "
        "the hand-off must cross a uid boundary",
        "same-owner hand-off",
    )
    os.chown(hubdir, hub.pw_uid, hub.pw_gid)
    os.chown(dest, hub.pw_uid, hub.pw_gid)

    os.chown(stage, 0, 0)
    expect_refused(
        binary, src, dest,
        f"source directory {stage} is owned by root; the staging directory must belong to the unprivileged writer",
        "root-owned staging directory",
    )
    os.chown(stage, writer.pw_uid, writer.pw_gid)

    # 3. A polluted environment changes neither the outcome nor the output.
    poison = BASE / "poison"
    poison.mkdir(mode=0o700)
    (poison / "config.toml").write_text("this is = = not toml [[[")
    (poison / "not-a-db.db").write_bytes(b"not a sqlite database")
    env = {
        "HOME": str(poison),
        "XDG_CONFIG_HOME": str(poison),
        "AI_MEMORY_CONFIG": str(poison / "config.toml"),
        "AI_MEMORY_DB": str(poison / "not-a-db.db"),
        "AI_MEMORY_AGENT_ID": "ai:mallory",
        "AI_MEMORY_LOG_DIR": str(poison / "logs"),
        "AI_MEMORY_KEY_DIR": str(poison / "keys"),
        "RUST_LOG": "trace",
        "PATH": "/nonexistent",
    }
    place(src, snapshot_bytes(), writer)
    rc, out, err, _ = publish(binary, src, dest, env)
    check(rc == EXIT_PUBLISHED, f"polluted env: publish exits 0 (got {rc}: {err})")
    check(out == clean_out, "polluted env: identical report line")
    check(err == "", "polluted env: nothing on stderr")
    check(
        sorted(p.name for p in poison.iterdir()) == ["config.toml", "not-a-db.db"],
        "polluted env: no log, key or database file was created",
    )
    st = os.lstat(dest)
    check(
        (st.st_uid, stat.S_IMODE(st.st_mode)) == (hub.pw_uid, 0o600),
        "polluted env: published owned by the hub uid at 0600",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--bin", required=True, type=Path, help="the ai-memory binary under test")
    args = parser.parse_args()
    if os.geteuid() != 0:
        print("wake_hub_publish_root_3971: must run as root (CI only)", file=sys.stderr)
        return 2
    if os.environ.get("GITHUB_ACTIONS") != "true":
        print("wake_hub_publish_root_3971: refuses to run outside a CI runner", file=sys.stderr)
        return 2
    binary = args.bin.resolve()
    try:
        run(binary)
    except (CheckFailed, subprocess.TimeoutExpired, OSError, subprocess.CalledProcessError) as exc:
        print(f"FAIL {exc}", file=sys.stderr)
        return 1
    finally:
        if BASE.exists():
            shutil.rmtree(BASE, ignore_errors=True)
        for name in (WRITER, HUB):
            subprocess.run(["userdel", name], check=False, capture_output=True)
    print("wake_hub_publish_root_3971: all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
