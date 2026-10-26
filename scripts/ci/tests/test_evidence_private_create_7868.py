#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""LOW7868: staged files are created private (0600); only the verified publication modes widen them."""
import os
import stat
import unittest
import unittest.mock as mock

from test_evidence_generator_5040_5042 import ScratchCase, load

PRIVATE_FILE_CREATE_MODE = 0o600
PUBLISHED_DATA_MODE = 0o644
PUBLISHED_SCRIPT_MODE = 0o755
GROUP_OTHER_BITS = stat.S_IRWXG | stat.S_IRWXO
FILES = {"proof.txt": b"approved\n", "run.sh": b"#!/bin/sh\n", "tool.py": b"print(1)\n"}


class PrivateCreate7868(ScratchCase):
    def publish(self, name, native=True):
        bundle = load("build_bundle")
        checkout = self.dir / name
        checkout.mkdir()
        dest = checkout / "published"
        created = []
        real_open = os.open

        def recording_open(path, flags, *rest, **kw):
            if flags & os.O_CREAT:
                created.append((path, rest[0] if rest else kw.get("mode")))
            return real_open(path, flags, *rest, **kw)

        patches = [mock.patch.object(os, "open", side_effect=recording_open)]
        if not native:
            patches.append(mock.patch.object(bundle, "rename_noreplace_native", None))
        with patches[0]:
            if native:
                bundle.publish_bundle(checkout, dest, FILES, bundle.manifest_text(FILES))
            else:
                with patches[1]:
                    bundle.publish_bundle(checkout, dest, FILES, bundle.manifest_text(FILES))
        return dest, created

    def test_creation_mode_is_private_native_7868(self):
        _, created = self.publish("native")
        self.assertEqual(len(created), len(FILES) + 1)
        for path, mode in created:
            with self.subTest(path=path):
                self.assertEqual(mode & GROUP_OTHER_BITS, 0)
                self.assertEqual(mode, PRIVATE_FILE_CREATE_MODE)

    def test_creation_mode_is_private_portable_7868(self):
        _, created = self.publish("portable", native=False)
        self.assertEqual(len(created), 2 * (len(FILES) + 1))  # the stage, then the exclusive claim
        for path, mode in created:
            with self.subTest(path=path):
                self.assertEqual(mode, PRIVATE_FILE_CREATE_MODE)

    def test_published_modes_are_unchanged_7868(self):
        dest, _ = self.publish("modes")
        self.assertEqual(stat.S_IMODE((dest / "proof.txt").stat().st_mode), PUBLISHED_DATA_MODE)
        self.assertEqual(stat.S_IMODE((dest / "MANIFEST.sha256").stat().st_mode), PUBLISHED_DATA_MODE)
        self.assertEqual(stat.S_IMODE((dest / "run.sh").stat().st_mode), PUBLISHED_SCRIPT_MODE)
        self.assertEqual(stat.S_IMODE((dest / "tool.py").stat().st_mode), PUBLISHED_SCRIPT_MODE)


if __name__ == "__main__":
    unittest.main()
