# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""The agent private key on disk is refused unless it is owner-only (#3784).

Before this fix ``AgentSigningKey.from_file`` was
``cls(Path(path).read_bytes())`` — no regular-file check, no
``mode & 0o077`` check, no owner check, and no ``O_NOFOLLOW``. A key file left
world-readable by a copy, a backup or a bad umask signed attestations with a
key any local uid could read, and the SDK said nothing; the daemon's own
loader (``src/identity/keypair.rs::read_private_key_file``) refused the
identical file, and so did this SDK's wake bundle loader (#3780). The fix
routes both loaders through ONE reader, :mod:`ai_memory._ownedfile`.

Each refusal cell below FAILS against the pre-#3784 ``from_file``:

* 0644 key      → loaded and signed happily            (DID NOT RAISE)
* symlinked key → followed the link and loaded the target (DID NOT RAISE)
* directory     → bare ``IsADirectoryError`` from ``read_bytes``, not a refusal

and the allowed-path control passes before and after, so it is a control and
not a second copy of the refusal.

The FIFO/parking leg of the shared reader is pinned once, on the wake side
(``test_wake_client.py``); it now exercises this same code path, so it is not
duplicated here (a FIFO cell would also PARK the pre-fix loader forever rather
than fail it, which is evidence of nothing).
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path

import pytest

from ai_memory.errors import AiMemoryError

pytest.importorskip(
    "cryptography",
    reason="attestation extra not installed (pip install 'ai-memory-mcp[attestation]')",
)

from ai_memory.attestation import AgentSigningKey  # after importorskip, by design

_SEED_LEN = 32


def _write_key(path: Path, seed: bytes, mode: int = 0o600) -> Path:
    """Write a raw 32-byte seed the way ``ai-memory identity generate`` does."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "wb") as fh:
        fh.write(seed)
    path.chmod(mode)
    return path


@pytest.fixture()
def key_file(tmp_path: Path) -> tuple[Path, bytes]:
    seed = secrets.token_bytes(_SEED_LEN)
    return _write_key(tmp_path / "agent.priv", seed), seed


@pytest.mark.skipif(os.name != "posix", reason="mode bits and O_NOFOLLOW are POSIX-only")
def test_a_group_or_world_readable_key_file_is_refused(key_file: tuple[Path, bytes]) -> None:
    """(a) 0644 — the exact shape a bad umask or a restored backup leaves."""
    path, seed = key_file
    path.chmod(0o644)

    with pytest.raises(AiMemoryError, match="must be 0600") as excinfo:
        AgentSigningKey.from_file(path)

    message = str(excinfo.value)
    assert str(path) in message, "the refusal must name the file the operator has to fix"
    assert "0644" in message, "the refusal must name the offending mode"
    # A refusal is a log line. It never renders the credential it refused.
    assert seed.hex() not in message
    assert repr(seed) not in message

    # And the same file, restored to 0600, loads — so what is refused is the
    # MODE, not the file.
    path.chmod(0o600)
    assert AgentSigningKey.from_file(path).seed_bytes() == seed


@pytest.mark.skipif(os.name != "posix", reason="mode bits and O_NOFOLLOW are POSIX-only")
def test_a_symlinked_key_file_is_refused(key_file: tuple[Path, bytes], tmp_path: Path) -> None:
    """(b) A link's permissions were checked on the wrong file, always."""
    path, _ = key_file
    link = tmp_path / "link.priv"
    link.symlink_to(path)

    with pytest.raises(AiMemoryError, match="symlink") as excinfo:
        AgentSigningKey.from_file(link)

    assert str(link) in str(excinfo.value)


@pytest.mark.skipif(os.name != "posix", reason="mode bits and O_NOFOLLOW are POSIX-only")
def test_a_directory_at_the_key_path_is_refused_as_not_a_regular_file(tmp_path: Path) -> None:
    """(c) Not a bare OSError from deep inside a read: a named refusal."""
    directory = tmp_path / "agent.priv"
    directory.mkdir()

    with pytest.raises(AiMemoryError, match="not a regular file") as excinfo:
        AgentSigningKey.from_file(directory)

    assert str(directory) in str(excinfo.value)


def test_an_owner_only_key_still_loads_and_signs(key_file: tuple[Path, bytes]) -> None:
    """(d) ALLOWED-PATH CONTROL — a 0600, caller-owned key is untouched.

    Passes against the pre-#3784 loader too. Without it the three cells above
    would be satisfied by a loader that refuses everything.
    """
    from cryptography.hazmat.primitives.asymmetric import ed25519

    path, seed = key_file
    key = AgentSigningKey.from_file(path)
    assert key.seed_bytes() == seed

    transcript = b"ai-memory/write/v1 control"
    signature = key.sign(transcript)
    ed25519.Ed25519PublicKey.from_public_bytes(key.public_key_bytes()).verify(
        signature, transcript
    )


@pytest.mark.skipif(os.name != "posix", reason="mode bits and O_NOFOLLOW are POSIX-only")
def test_the_refusal_is_the_sdks_own_error_type(key_file: tuple[Path, bytes]) -> None:
    """The refusal type is dedicated and is an :class:`AiMemoryError`.

    Imported inside the body on purpose: the class does not exist before
    #3784, and a module-level import of it would turn the red-first run of the
    cells above into a collection error instead of the clean DID-NOT-RAISE
    that proves the pre-fix loader accepted the file.
    """
    from ai_memory.attestation import KeyFileError

    assert issubclass(KeyFileError, AiMemoryError)
    path, _ = key_file
    path.chmod(0o604)
    with pytest.raises(KeyFileError):
        AgentSigningKey.from_file(path)


@pytest.mark.skipif(os.name != "posix", reason="mode bits and O_NOFOLLOW are POSIX-only")
def test_the_key_loader_and_the_wake_bundle_loader_are_one_reader(tmp_path: Path) -> None:
    """Both credential loaders reach the SAME checker, on a DESCRIPTOR's stat.

    Two loaders of local private keys with two standards is how the weaker one
    survives; #3784 left exactly one. The spy records what was checked, so
    this cannot be satisfied by a second, look-alike copy of the checks.
    """
    from ai_memory import _ownedfile, wake

    key_path = _write_key(tmp_path / "agent.priv", secrets.token_bytes(_SEED_LEN), 0o640)
    bundle_path = tmp_path / "agent.a2a-hub.json"
    bundle_path.write_text("{}", encoding="utf-8")
    bundle_path.chmod(0o640)

    seen: list[tuple[Path, int, int]] = []
    real = _ownedfile.check_owned_stat

    def spy(p: Path, st: os.stat_result, **kwargs: object) -> None:
        seen.append((p, st.st_ino, st.st_mode))
        real(p, st, **kwargs)  # type: ignore[arg-type]

    _ownedfile.check_owned_stat = spy  # type: ignore[assignment]
    try:
        with pytest.raises(AiMemoryError, match="must be 0600"):
            AgentSigningKey.from_file(key_path)
        with pytest.raises(wake.WakeError, match="must be 0600"):
            wake.DelegationBundle.load(bundle_path)
    finally:
        _ownedfile.check_owned_stat = real  # type: ignore[assignment]

    assert [entry[0] for entry in seen] == [key_path, bundle_path], (
        "both loaders must reach the shared checker, exactly once each"
    )
    # Each stat that was checked is the DESCRIPTOR's, bound to the same inode
    # that would have been read — not a second look at the path.
    assert seen[0][1] == key_path.stat().st_ino
    assert seen[1][1] == bundle_path.stat().st_ino
