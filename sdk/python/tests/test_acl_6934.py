# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Extended ACLs in the CA-path rule and the owner-only reader, round 8 of #6060 (#6934).

Both rules said "only this user or root can change (or read) it" and read mode
bits alone. On macOS an extended ACL grants another account that right while the
mode bits stay ``0755`` / ``0644`` / ``0600``: the round-7 reviews trusted a CA
another account could replace, and accepted a key another account could read.

The real-ACL tests build the ACL with ``chmod +a`` and run only on a macOS
filesystem that supports it (they skip, with the reason, elsewhere). The wiring
tests replace the ACL reader with a stub so every call site is pinned on every
platform.
"""

from __future__ import annotations

import getpass
import os
import pathlib
import secrets
import shutil
import subprocess
import sys
from types import SimpleNamespace
from typing import Any, Callable, Iterator

import certifi
import pytest

from ai_memory import _acl, _common
from ai_memory.errors import AiMemoryError
from ai_memory.wake import DelegationBundle, WakeError

from .test_tls_session_6060_r5 import _CLIENTS, _POSIX_ONLY, _built, _ca_dir

pytest.importorskip(
    "cryptography",
    reason="attestation extra not installed (pip install 'ai-memory-mcp[attestation]')",
)

from ai_memory.attestation import AgentSigningKey  # after importorskip, by design

_ENTRY = "deadbeef.0"  # a name the hashed-CA-directory rule loads
_DIR_ALLOW = "everyone allow add_file,delete_child,add_subdirectory"
_FILE_ALLOW = "everyone allow write,append"
_READ_ALLOW = "everyone allow read"


def _chmod_acl(path: pathlib.Path, entry: str) -> None:
    subprocess.run(["chmod", "+a", entry, str(path)], check=True)  # noqa: S603,S607 - fixed argv


@pytest.fixture
def acl_fs(tmp_path: pathlib.Path) -> pathlib.Path:
    """``tmp_path`` once ``chmod +a`` is known to work on its filesystem."""
    if sys.platform != "darwin":
        pytest.skip("extended ACL entries are a macOS surface (POSIX ACLs show in the mode bits)")
    probe = tmp_path / "acl-probe"
    probe.write_bytes(b"")
    try:
        _chmod_acl(probe, _READ_ALLOW)
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("this filesystem does not support extended ACLs (chmod +a failed)")
    probe.unlink()
    return tmp_path


def _ca(directory: pathlib.Path, name: str = "ca.pem") -> pathlib.Path:
    """A 0644 CA bundle (anchors the caller never named) in ``directory``."""
    bundle = directory / name
    shutil.copy(certifi.where(), bundle)
    bundle.chmod(0o644)
    return bundle


def _key(directory: pathlib.Path) -> pathlib.Path:
    path = directory / "agent.priv"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(secrets.token_bytes(32))
    path.chmod(0o600)
    return path


# ---- real ACLs: the CA-path rule ------------------------------------------


@pytest.mark.parametrize("client_cls", _CLIENTS)
def test_acl_on_the_ca_files_directory_is_refused_6934(
    acl_fs: pathlib.Path, client_cls: type
) -> None:
    """A 0755 directory whose ACL lets everyone add/delete entries: another user replaces ca.pem."""
    directory = _ca_dir(acl_fs)
    _ca(directory)
    _chmod_acl(directory, _DIR_ALLOW)
    with pytest.raises(ValueError, match="ACL") as refused:
        _built(client_cls, str(directory / "ca.pem"))
    assert "#6934" in str(refused.value)


@pytest.mark.parametrize("client_cls", _CLIENTS)
def test_acl_on_the_ca_file_is_refused_6934(acl_fs: pathlib.Path, client_cls: type) -> None:
    """A 0644 CA file whose ACL lets everyone write: another user rewrites the anchors."""
    directory = _ca_dir(acl_fs)
    bundle = _ca(directory)
    _chmod_acl(bundle, _FILE_ALLOW)
    with pytest.raises(ValueError, match="ACL"):
        _built(client_cls, str(bundle))


@pytest.mark.parametrize("client_cls", _CLIENTS)
def test_acl_on_an_ancestor_of_the_ca_path_is_refused_6934(
    acl_fs: pathlib.Path, client_cls: type
) -> None:
    """The rule is for EVERY directory the path passes through, not only the last."""
    outer = _ca_dir(acl_fs, "outer")
    inner = outer / "inner"
    inner.mkdir()
    inner.chmod(0o755)
    _ca(inner)
    _chmod_acl(outer, _DIR_ALLOW)
    with pytest.raises(ValueError, match="ACL"):
        _built(client_cls, str(inner / "ca.pem"))


@pytest.mark.parametrize("client_cls", _CLIENTS)
def test_acl_on_a_hashed_ca_directory_is_refused_6934(
    acl_fs: pathlib.Path, client_cls: type
) -> None:
    """The directory named by ``verify=`` is held to the rule even when it is empty."""
    directory = _ca_dir(acl_fs, "hashed")
    _chmod_acl(directory, _DIR_ALLOW)
    with pytest.raises(ValueError, match="ACL"):
        _built(client_cls, str(directory))


@pytest.mark.parametrize("client_cls", _CLIENTS)
def test_acl_on_an_entry_of_a_hashed_ca_directory_is_refused_6934(
    acl_fs: pathlib.Path, client_cls: type
) -> None:
    directory = _ca_dir(acl_fs, "hashed")
    entry = _ca(directory, _ENTRY)
    _chmod_acl(entry, _FILE_ALLOW)
    with pytest.raises(ValueError, match="ACL"):
        _built(client_cls, str(directory))


@pytest.mark.parametrize("client_cls", _CLIENTS)
def test_group_acl_write_is_refused_6934(acl_fs: pathlib.Path, client_cls: type) -> None:
    """A group principal is never this user: its members are not ours to vouch for."""
    directory = _ca_dir(acl_fs)
    bundle = _ca(directory)
    _chmod_acl(bundle, "group:staff allow write")
    with pytest.raises(ValueError, match="ACL"):
        _built(client_cls, str(bundle))


@pytest.mark.parametrize("client_cls", _CLIENTS)
def test_group_zero_acl_write_is_refused_not_mistaken_for_root_6934(
    acl_fs: pathlib.Path, client_cls: type
) -> None:
    """``group:wheel`` is gid 0: an id-only comparison would take it for the user root."""
    directory = _ca_dir(acl_fs)
    bundle = _ca(directory)
    try:
        _chmod_acl(bundle, "group:wheel allow write")
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("this host has no group named wheel")
    with pytest.raises(ValueError, match="ACL"):
        _built(client_cls, str(bundle))


@pytest.mark.parametrize("client_cls", _CLIENTS)
def test_root_user_acl_write_is_not_a_foreign_principal_6934(
    acl_fs: pathlib.Path, client_cls: type
) -> None:
    """Control for the group-zero test: the USER root may hold the right (it can change any file)."""
    directory = _ca_dir(acl_fs)
    bundle = _ca(directory)
    try:
        _chmod_acl(bundle, "user:root allow write")
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("this host has no user named root")
    _built(client_cls, str(bundle))


@pytest.mark.parametrize(
    "entry",
    [
        pytest.param("everyone allow read", id="read-only"),
        pytest.param("everyone deny chown", id="deny-only"),
        pytest.param("user:{me} allow write,append,delete", id="own-user-write"),
    ],
)
@pytest.mark.parametrize("client_cls", _CLIENTS)
def test_acl_that_grants_no_one_else_write_is_accepted_6934(
    acl_fs: pathlib.Path, client_cls: type, entry: str
) -> None:
    """Controls: the refusal is for rights granted to someone else, not for any ACL."""
    directory = _ca_dir(acl_fs)
    bundle = _ca(directory)
    me = getpass.getuser()
    _chmod_acl(directory, entry.format(me=me))
    _chmod_acl(bundle, entry.format(me=me))
    _built(client_cls, str(bundle))


# ---- real ACLs: the owner-only reader -------------------------------------


def test_key_readable_through_an_acl_is_refused_6934(acl_fs: pathlib.Path) -> None:
    """A 0600 private key whose ACL lets everyone read it: another user forges attestations."""
    key = _key(acl_fs)
    _chmod_acl(key, _READ_ALLOW)
    with pytest.raises(AiMemoryError, match="ACL") as refused:
        AgentSigningKey.from_file(key)
    assert str(key) in str(refused.value)


def test_key_with_a_group_acl_write_is_refused_6934(acl_fs: pathlib.Path) -> None:
    key = _key(acl_fs)
    _chmod_acl(key, "group:staff allow write,writesecurity")
    with pytest.raises(AiMemoryError, match="ACL"):
        AgentSigningKey.from_file(key)


def test_delegation_bundle_readable_through_an_acl_is_refused_6934(
    acl_fs: pathlib.Path,
) -> None:
    bundle = acl_fs / "agent.a2a-hub.json"
    bundle.write_text("{}", encoding="utf-8")
    bundle.chmod(0o600)
    _chmod_acl(bundle, _READ_ALLOW)
    with pytest.raises(WakeError, match="ACL"):
        DelegationBundle.load(bundle)


@pytest.mark.parametrize(
    "entry",
    [
        pytest.param("everyone deny chown", id="deny-only"),
        pytest.param("user:{me} allow read,write", id="own-user"),
    ],
)
def test_key_acl_that_grants_no_one_else_anything_is_accepted_6934(
    acl_fs: pathlib.Path, entry: str
) -> None:
    key = _key(acl_fs)
    _chmod_acl(key, entry.format(me=getpass.getuser()))
    assert AgentSigningKey.from_file(key) is not None


def test_acl_reader_fails_closed_on_a_descriptor_it_cannot_read_6934(
    acl_fs: pathlib.Path,
) -> None:
    del acl_fs  # only its skip conditions
    with pytest.raises(_acl.AclUnreadable):
        _acl.foreign_acl_rights(-1, _acl.CHANGE_RIGHTS)


def test_acl_reader_reports_the_rights_it_found_6934(acl_fs: pathlib.Path) -> None:
    directory = _ca_dir(acl_fs)
    _chmod_acl(directory, "everyone allow add_file,delete_child")
    fd = os.open(directory, os.O_RDONLY)
    try:
        found = _acl.foreign_acl_rights(fd, _acl.CHANGE_RIGHTS | _acl.ACL_READ_DATA)
    finally:
        os.close(fd)
    assert found == _acl.ACL_WRITE_DATA | _acl.ACL_DELETE_CHILD


# ---- every platform: the call sites, with the reader stubbed --------------


@pytest.fixture
def stub_acl(monkeypatch: pytest.MonkeyPatch) -> Iterator[SimpleNamespace]:
    """Make the ACL layer active and let a test decide what it reports per descriptor."""
    state = SimpleNamespace(rule=lambda fd, rights: 0, calls=[])

    def foreign(fd: int, rights: int) -> int:
        state.calls.append((os.fstat(fd), rights))
        return int(state.rule(fd, rights))

    monkeypatch.setattr(_acl, "reads_acls", lambda: True)
    monkeypatch.setattr(_acl, "foreign_acl_rights", foreign)
    yield state


def _only(path: pathlib.Path, granted: int) -> Callable[[int, int], int]:
    """A rule that reports ``granted`` for the object at ``path`` (by inode) and ``0`` elsewhere."""
    found = os.stat(path)

    def rule(fd: int, rights: int) -> int:
        now = os.fstat(fd)
        return granted & rights if (now.st_dev, now.st_ino) == (found.st_dev, found.st_ino) else 0

    return rule


@_POSIX_ONLY
@pytest.mark.parametrize("client_cls", _CLIENTS)
def test_stubbed_acl_on_the_holder_directory_refuses_the_ca_6934(
    tmp_path: pathlib.Path, stub_acl: SimpleNamespace, client_cls: type
) -> None:
    directory = _ca_dir(tmp_path)
    bundle = _ca(directory)
    _built(client_cls, str(bundle))  # control: the stub grants nothing yet
    assert stub_acl.calls, "the ACL layer must be consulted for a CA path"
    stub_acl.rule = _only(directory, _acl.ACL_WRITE_DATA | _acl.ACL_DELETE_CHILD)
    with pytest.raises(ValueError, match="ACL"):
        _built(client_cls, str(bundle))


@_POSIX_ONLY
@pytest.mark.parametrize("client_cls", _CLIENTS)
def test_stubbed_acl_on_an_ancestor_refuses_the_ca_6934(
    tmp_path: pathlib.Path, stub_acl: SimpleNamespace, client_cls: type
) -> None:
    outer = _ca_dir(tmp_path, "outer")
    inner = outer / "inner"
    inner.mkdir()
    inner.chmod(0o755)
    bundle = _ca(inner)
    stub_acl.rule = _only(outer, _acl.ACL_DELETE_CHILD)
    with pytest.raises(ValueError, match="ACL"):
        _built(client_cls, str(bundle))


@_POSIX_ONLY
@pytest.mark.parametrize("client_cls", _CLIENTS)
def test_stubbed_acl_on_the_ca_file_refuses_the_ca_6934(
    tmp_path: pathlib.Path, stub_acl: SimpleNamespace, client_cls: type
) -> None:
    directory = _ca_dir(tmp_path)
    bundle = _ca(directory)
    stub_acl.rule = _only(bundle, _acl.ACL_WRITE_DATA)
    with pytest.raises(ValueError, match="ACL"):
        _built(client_cls, str(bundle))


@_POSIX_ONLY
@pytest.mark.parametrize("client_cls", _CLIENTS)
def test_stubbed_acl_on_the_named_ca_directory_refuses_the_ca_6934(
    tmp_path: pathlib.Path, stub_acl: SimpleNamespace, client_cls: type
) -> None:
    directory = _ca_dir(tmp_path, "hashed")
    _ca(directory, _ENTRY)
    _built(client_cls, str(directory))  # control
    stub_acl.rule = _only(directory, _acl.ACL_APPEND_DATA)
    with pytest.raises(ValueError, match="ACL"):
        _built(client_cls, str(directory))


@_POSIX_ONLY
@pytest.mark.parametrize("client_cls", _CLIENTS)
def test_stubbed_acl_on_a_hashed_entry_refuses_the_ca_6934(
    tmp_path: pathlib.Path, stub_acl: SimpleNamespace, client_cls: type
) -> None:
    directory = _ca_dir(tmp_path, "hashed")
    entry = _ca(directory, _ENTRY)
    stub_acl.rule = _only(entry, _acl.ACL_DELETE)
    with pytest.raises(ValueError, match="ACL"):
        _built(client_cls, str(directory))


@_POSIX_ONLY
@pytest.mark.parametrize("client_cls", _CLIENTS)
@pytest.mark.parametrize("which", ["holder", "file"])
def test_unreadable_acl_refuses_the_ca_fail_closed_6934(
    tmp_path: pathlib.Path,
    stub_acl: SimpleNamespace,
    monkeypatch: pytest.MonkeyPatch,
    client_cls: type,
    which: str,
) -> None:
    directory = _ca_dir(tmp_path)
    bundle = _ca(directory)
    target = directory if which == "holder" else bundle
    found = os.stat(target)

    def foreign(fd: int, rights: int) -> int:
        now = os.fstat(fd)
        if (now.st_dev, now.st_ino) == (found.st_dev, found.st_ino):
            raise _acl.AclUnreadable("acl_get_fd_np failed: Input/output error")
        return 0

    monkeypatch.setattr(_acl, "foreign_acl_rights", foreign)
    with pytest.raises(ValueError, match="cannot be read") as refused:
        _built(client_cls, str(bundle))
    assert "#6934" in str(refused.value)


@_POSIX_ONLY
def test_ca_checks_do_not_read_acls_where_the_platform_has_none_6934(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When ``reads_acls()`` is false no descriptor is opened for it and nothing is asked."""
    directory = _ca_dir(tmp_path)
    bundle = _ca(directory)
    asked: list[int] = []
    monkeypatch.setattr(_acl, "reads_acls", lambda: False)
    monkeypatch.setattr(_acl, "foreign_acl_rights", lambda fd, rights: asked.append(fd) or 0)
    _common._checked_verify(str(bundle))
    assert asked == []


@_POSIX_ONLY
def test_stubbed_acl_read_right_refuses_the_key_6934(
    tmp_path: pathlib.Path, stub_acl: SimpleNamespace
) -> None:
    key = _key(tmp_path)
    assert AgentSigningKey.from_file(key) is not None  # control
    assert stub_acl.calls[-1][1] & _acl.ACL_READ_DATA, "the key reader must ask for read rights"
    stub_acl.rule = _only(key, _acl.ACL_READ_DATA)
    with pytest.raises(AiMemoryError, match="ACL"):
        AgentSigningKey.from_file(key)


@_POSIX_ONLY
def test_stubbed_acl_change_right_refuses_the_key_6934(
    tmp_path: pathlib.Path, stub_acl: SimpleNamespace
) -> None:
    key = _key(tmp_path)
    stub_acl.rule = _only(key, _acl.ACL_WRITE_SECURITY)
    with pytest.raises(AiMemoryError, match="ACL"):
        AgentSigningKey.from_file(key)


@_POSIX_ONLY
def test_unreadable_acl_refuses_the_key_fail_closed_6934(
    tmp_path: pathlib.Path, stub_acl: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = _key(tmp_path)
    descriptors: list[Any] = []

    def foreign(fd: int, rights: int) -> int:
        descriptors.append(fd)
        raise _acl.AclUnreadable("acl_get_fd_np failed: Input/output error")

    monkeypatch.setattr(_acl, "foreign_acl_rights", foreign)
    with pytest.raises(AiMemoryError, match="cannot be read"):
        AgentSigningKey.from_file(key)
    assert descriptors, "the key reader must consult the ACL layer"
    with pytest.raises(WakeError, match="cannot be read"):
        DelegationBundle.load(key)


@_POSIX_ONLY
def test_acl_is_read_from_the_directory_the_mode_rules_judged_6934(
    tmp_path: pathlib.Path, stub_acl: SimpleNamespace
) -> None:
    """The directory opened for its ACL must be the inode ``held`` describes (swap between stat and open)."""
    judged = _ca_dir(tmp_path, "judged")
    swapped_in = _ca_dir(tmp_path, "swapped-in")
    _common._refuse_foreign_acl_on_directory("CA path", str(judged), str(judged), os.stat(judged))
    with pytest.raises(ValueError, match="changed while its ACL was being read"):
        _common._refuse_foreign_acl_on_directory(
            "CA path", str(judged), str(swapped_in), os.stat(judged)
        )
