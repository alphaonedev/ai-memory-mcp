# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Seam for the extended-ACL reader (#6934): constants and a reader that sees no ACL."""

from __future__ import annotations

__all__ = ["AclUnreadable", "foreign_acl_rights", "reads_acls"]

ACL_READ_DATA = 1 << 1
ACL_WRITE_DATA = 1 << 2
ACL_DELETE = 1 << 4
ACL_APPEND_DATA = 1 << 5
ACL_DELETE_CHILD = 1 << 6
ACL_WRITE_SECURITY = 1 << 12
ACL_CHANGE_OWNER = 1 << 13
CHANGE_RIGHTS = (
    ACL_WRITE_DATA
    | ACL_APPEND_DATA
    | ACL_DELETE
    | ACL_DELETE_CHILD
    | ACL_WRITE_SECURITY
    | ACL_CHANGE_OWNER
)


class AclUnreadable(Exception):  # noqa: N818 - a refusal reason, not an error class
    """The ACL of an open object could not be read."""


def reads_acls() -> bool:
    return False


def foreign_acl_rights(fd: int, rights: int) -> int:
    return 0
