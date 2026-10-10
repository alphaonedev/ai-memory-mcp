"""Kill tests for the surviving #6934 ACL mutants (round-8 security review, macOS only).

Each test pins one fail-closed or principal rule of ai_memory._acl / _common that test_acl_6934.py
leaves unpinned: a chown grant, a named foreign USER grant, each libSystem failure path, the
directory open's O_NOFOLLOW and the directory that cannot be opened. Failures are injected by
wrapping the real libSystem handle; real ACLs are set with chmod +a on files this user owns.
Run from sdk/python: python -m pytest -q <this file>
"""

import ctypes
import errno
import os
import subprocess
import sys

import pytest

from ai_memory import _acl, _common

pytestmark = pytest.mark.skipif(
    sys.platform != "darwin", reason="extended ACLs are read on macOS only"
)


def _acl_file(tmp_path, entry):
    f = tmp_path / "f"
    f.write_text("x")
    f.chmod(0o644)
    subprocess.run(["/bin/chmod", "+a", entry, str(f)], check=True)
    return f


def _rights(path, rights=_acl.CHANGE_RIGHTS):
    fd = os.open(str(path), os.O_RDONLY)
    try:
        return _acl.foreign_acl_rights(fd, rights)
    finally:
        os.close(fd)


class _Lib:
    """The real libSystem handle with one call replaced."""

    def __init__(self, real, name, fake):
        self._real, self._name, self._fake = real, name, fake

    def __getattr__(self, attr):
        return self._fake if attr == self._name else getattr(self._real, attr)


def _break(monkeypatch, name, result):
    real_libc = _acl._libc

    def fake(*_a):
        ctypes.set_errno(errno.EIO)
        return result

    monkeypatch.setattr(_acl, "_libc", lambda: _Lib(real_libc(), name, fake))


def test_chown_grant_to_another_user_is_a_foreign_right(tmp_path):  # kills R06
    f = _acl_file(tmp_path, "user:nobody allow chown")
    assert _rights(f) & _acl.ACL_CHANGE_OWNER


def test_write_grant_to_a_named_foreign_user_is_a_foreign_right(tmp_path):  # kills R13
    f = _acl_file(tmp_path, "user:nobody allow write")
    assert _rights(f) & _acl.ACL_WRITE_DATA


@pytest.mark.parametrize(
    "call,result",
    [
        ("mbr_uuid_to_id", 1),  # kills R08
        ("acl_get_qualifier", None),  # kills R09
        ("acl_get_entry", -1),  # kills R10
        ("acl_get_tag_type", -1),  # kills R11
        ("acl_get_permset_mask_np", -1),  # kills R12
    ],
)
def test_each_libsystem_failure_is_unreadable_not_no_acl(tmp_path, monkeypatch, call, result):
    f = _acl_file(tmp_path, "user:nobody allow write")
    _break(monkeypatch, call, result)
    with pytest.raises(_acl.AclUnreadable):
        _rights(f)


def test_directory_acl_open_does_not_follow_a_symlink(tmp_path):  # kills R15
    target = tmp_path / "d"
    target.mkdir()
    link = tmp_path / "l"
    os.symlink(target, link)
    with pytest.raises(ValueError, match="cannot be opened"):
        _common._refuse_foreign_acl_on_directory("CA path", str(link), str(link), os.stat(target))


def test_directory_that_cannot_be_opened_is_refused(tmp_path):  # kills R16
    held = os.stat(tmp_path)
    with pytest.raises(ValueError, match="cannot be opened"):
        _common._refuse_foreign_acl_on_directory(
            "CA path", str(tmp_path), str(tmp_path / "gone"), held
        )
