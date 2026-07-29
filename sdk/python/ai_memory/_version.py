# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Single source of truth for the Python SDK version (#2455).

This module contains NOTHING but the version literal, deliberately:
``pyproject.toml`` declares ``dynamic = ["version"]`` and reads the value
straight out of here via ``[tool.setuptools.dynamic]``, which setuptools
resolves with a STATIC AST read — so this file must stay import-free (no
``httpx`` / ``pydantic``) for the build backend to parse it without
installing the runtime dependencies.

Before #2455 the version was asserted in four places that had drifted to
three different answers:

* ``pyproject.toml:10``           -> ``1.0.0``
* ``ai_memory/__init__.py:60``    -> ``0.8.0``
* ``_common.py:52`` (User-Agent)  -> ``0.6.0-alpha.0``
* ``README.md:8``                 -> ``0.6.0-alpha.0 - scaffolding, unpublished``

A published wheel therefore reported one version to PyPI, another to
``ai_memory.__version__``, and a third in the ``User-Agent`` every daemon
logged — making server-side triage of a client bug actively misleading.
All four now derive from this literal (the README quotes it and is pinned by
``tests/test_version.py``).

Bump HERE and nowhere else.
"""

__version__ = "1.0.0"
