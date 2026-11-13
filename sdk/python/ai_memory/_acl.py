# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Extended-ACL rights on an open descriptor, for the SDK's owner-only rules (#6934).

Why this module exists
----------------------

Two SDK rules say "only this user or root can change (or read) it": the CA-path
rule of ``verify=`` (:mod:`ai_memory._common`) and the owner-only credential
reader (:mod:`ai_memory._ownedfile`). Both read POSIX mode bits. On macOS a
file or directory also carries an *extended ACL*, and an entry such as
``everyone allow add_file,delete_child`` lets another account change what is
under a ``0755`` directory while the mode bits still read ``rwxr-xr-x``; an
``everyone allow read`` entry lets another account read a ``0600`` key. Mode
bits alone describe neither, so a CA another account could replace was trusted
and a key another account could read was accepted.

Mechanism
---------

``decision: ctypes over libSystem's own ACL API over refusing every extended
ACL or shelling out to ls/ditto, because the question is "does an allow entry
grant this right to someone else", ctypes asks the kernel's own ACL object for
exactly that on the descriptor already open (no second path resolution, no
process spawn, no new dependency), and refusing every ACL would reject
/Users/<name> style directories that carry only a harmless deny entry.``

The ACL is read with ``acl_get_fd_np(fd, ACL_TYPE_EXTENDED)`` from the
platform C library, each entry's permission mask with
``acl_get_permset_mask_np`` and its principal with ``acl_get_qualifier`` plus
``mbr_uuid_to_id``. Only first-party code is used: :mod:`ctypes` from the
standard library.

Policy
------

* A *deny* entry grants nothing and is ignored. An *allow* entry that grants
  one of the asked-for rights counts unless its principal is a user who is
  this process's effective uid or root. A group principal always counts: its
  membership is not this process's to vouch for.
* Fail closed: an ACL that cannot be read, an entry whose tag, permission set
  or principal cannot be read, and a principal that cannot be mapped to an id
  each raise :class:`AclUnreadable`, which the callers turn into a typed
  refusal. The one non-error "no ACL" answer is ``ENOENT`` from
  ``acl_get_fd_np``, which is how the platform reports an object with no
  extended ACL.
* Other platforms: a POSIX ACL entry for a named user raises the mask, which
  shows in the group bits the mode rules already refuse, so there is nothing
  extra to read and the answer is "no foreign rights".
"""

from __future__ import annotations

import ctypes
import errno
import os
import sys
from typing import Any

__all__ = [
    "ACL_CHANGE_OWNER",
    "ACL_DELETE",
    "ACL_DELETE_CHILD",
    "ACL_APPEND_DATA",
    "ACL_READ_DATA",
    "ACL_WRITE_DATA",
    "ACL_WRITE_SECURITY",
    "AclUnreadable",
    "CHANGE_RIGHTS",
    "describe",
    "foreign_acl_rights",
    "reads_acls",
]

# <sys/acl.h> acl_perm_t bits (macOS).
ACL_READ_DATA = 1 << 1  # also ACL_LIST_DIRECTORY
ACL_WRITE_DATA = 1 << 2  # also ACL_ADD_FILE
ACL_DELETE = 1 << 4
ACL_APPEND_DATA = 1 << 5  # also ACL_ADD_SUBDIRECTORY
ACL_DELETE_CHILD = 1 << 6
ACL_WRITE_SECURITY = 1 << 12
ACL_CHANGE_OWNER = 1 << 13

#: Every ACL right that lets a principal change a file or directory, or give
#: itself any right: the rights the CA-path rule refuses to see held by anyone
#: but this user or root.
CHANGE_RIGHTS = (
    ACL_WRITE_DATA
    | ACL_APPEND_DATA
    | ACL_DELETE
    | ACL_DELETE_CHILD
    | ACL_WRITE_SECURITY
    | ACL_CHANGE_OWNER
)

_ACL_TYPE_EXTENDED = 0x00000100
_ACL_FIRST_ENTRY = 0
_ACL_NEXT_ENTRY = -1
_ACL_EXTENDED_ALLOW = 1
_ID_TYPE_UID = 0
_UUID_BYTES = 16


class AclUnreadable(Exception):  # noqa: N818 - a refusal reason, not an error class
    """The extended ACL of an open object could not be read or understood.

    Callers refuse the object (fail closed). The message names the failing
    call and its errno text only; it never carries file content.
    """


def _libc() -> Any:
    """The platform C library, with the ACL and membership prototypes declared."""
    lib = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    pointer = ctypes.c_void_p
    lib.acl_get_fd_np.restype = pointer
    lib.acl_get_fd_np.argtypes = [ctypes.c_int, ctypes.c_uint]
    lib.acl_get_entry.restype = ctypes.c_int
    lib.acl_get_entry.argtypes = [pointer, ctypes.c_int, ctypes.POINTER(pointer)]
    lib.acl_get_tag_type.restype = ctypes.c_int
    lib.acl_get_tag_type.argtypes = [pointer, ctypes.POINTER(ctypes.c_int)]
    lib.acl_get_permset_mask_np.restype = ctypes.c_int
    lib.acl_get_permset_mask_np.argtypes = [pointer, ctypes.POINTER(ctypes.c_uint64)]
    lib.acl_get_qualifier.restype = pointer
    lib.acl_get_qualifier.argtypes = [pointer]
    lib.acl_free.restype = ctypes.c_int
    lib.acl_free.argtypes = [pointer]
    lib.mbr_uuid_to_id.restype = ctypes.c_int
    lib.mbr_uuid_to_id.argtypes = [
        ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_uint),
        ctypes.POINTER(ctypes.c_int),
    ]
    return lib


def _unreadable(call: str) -> AclUnreadable:
    return AclUnreadable(f"{call} failed: {os.strerror(ctypes.get_errno())}")


def _scan(fd: int, rights: int) -> int:
    """The OR of ``rights`` that ALLOW entries on ``fd`` grant to a foreign principal."""
    lib = _libc()
    ctypes.set_errno(0)
    acl = lib.acl_get_fd_np(fd, _ACL_TYPE_EXTENDED)
    if not acl:
        if ctypes.get_errno() == errno.ENOENT:
            return 0  # the platform's answer for "no extended ACL"
        raise _unreadable("acl_get_fd_np")
    granted = 0
    trusted = (0, os.geteuid())
    try:
        entry = ctypes.c_void_p()
        position = _ACL_FIRST_ENTRY
        while True:
            status = lib.acl_get_entry(acl, position, ctypes.byref(entry))
            if status != 0:
                if status == -1 and ctypes.get_errno() in (0, errno.EINVAL):
                    break  # past the last entry (the API reports it as EINVAL)
                raise _unreadable("acl_get_entry")
            position = _ACL_NEXT_ENTRY
            tag = ctypes.c_int()
            if lib.acl_get_tag_type(entry, ctypes.byref(tag)) != 0:
                raise _unreadable("acl_get_tag_type")
            if tag.value != _ACL_EXTENDED_ALLOW:
                continue
            mask = ctypes.c_uint64()
            if lib.acl_get_permset_mask_np(entry, ctypes.byref(mask)) != 0:
                raise _unreadable("acl_get_permset_mask_np")
            wanted = int(mask.value) & rights
            if not wanted:
                continue
            if _principal_is_trusted_user(lib, entry, trusted):
                continue
            granted |= wanted
    finally:
        lib.acl_free(acl)
    return granted


def _principal_is_trusted_user(lib: Any, entry: Any, trusted: tuple[int, int]) -> bool:
    """Whether ``entry`` names a user that is this process's effective uid or root."""
    ctypes.set_errno(0)
    qualifier = lib.acl_get_qualifier(entry)
    if not qualifier:
        raise _unreadable("acl_get_qualifier")
    try:
        guid = ctypes.string_at(qualifier, _UUID_BYTES)
    finally:
        lib.acl_free(qualifier)
    ident = ctypes.c_uint()
    id_type = ctypes.c_int()
    if lib.mbr_uuid_to_id(guid, ctypes.byref(ident), ctypes.byref(id_type)) != 0:
        raise AclUnreadable("mbr_uuid_to_id failed: the ACL principal is unknown")
    return id_type.value == _ID_TYPE_UID and ident.value in trusted


_NAMES = (
    (ACL_READ_DATA, "read"),
    (ACL_WRITE_DATA, "write"),
    (ACL_APPEND_DATA, "append"),
    (ACL_DELETE, "delete"),
    (ACL_DELETE_CHILD, "delete_child"),
    (ACL_WRITE_SECURITY, "writesecurity"),
    (ACL_CHANGE_OWNER, "chown"),
)


def describe(rights: int) -> str:
    """The ``chmod +a`` words for the bits of ``rights``, for a refusal message."""
    return ",".join(name for bit, name in _NAMES if rights & bit)


def reads_acls() -> bool:
    """Whether this platform has an extended ACL this module reads (macOS)."""
    return sys.platform == "darwin"


def foreign_acl_rights(fd: int, rights: int) -> int:
    """The part of ``rights`` that an extended ACL on ``fd`` grants to someone else (#6934).

    ``0`` means the object is safe under the rule that asked. Only macOS has an
    extended ACL this reads; everywhere else the mode bits already carry the
    answer and this returns ``0``. Raises :class:`AclUnreadable` (fail closed)
    when the ACL exists but cannot be read.
    """
    if not reads_acls():
        return 0
    return _scan(fd, rights)
