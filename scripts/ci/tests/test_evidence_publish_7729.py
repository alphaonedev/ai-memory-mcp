#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Builder identity and expected-content regressions for issue #7729."""
import os
import stat
import unittest.mock as mock

from test_evidence_generator_5040_5042 import ScratchCase, load

MANIFEST = "MANIFEST.sha256"
ORIGINAL = {"a.txt": b"builder bytes\n"}
FORGED = {"a.txt": b"different bytes\n"}


class Publish7729(ScratchCase):
    def setUp(self):
        super().setUp()
        self.bb = load("build_bundle")
        self.wt = self.dir / "wt"
        self.wt.mkdir()
        self.scratch = self.wt / ".local-runs"
        self.scratch.mkdir(mode=0o775)
        self.scratch.chmod(0o775)
        self.dest = self.wt / "evidence" / "cert-test"
        self.manifest = self.bb.manifest_text(ORIGINAL)

    def publish(self):
        return self.bb.publish_bundle(self.wt, self.dest, dict(ORIGINAL), self.manifest)

    def forge(self, path):
        for name, data in FORGED.items():
            (path / name).write_bytes(data)
        (path / MANIFEST).write_text(self.bb.manifest_text(FORGED))

    def attack(self, mutate):
        real = self.bb.stage_verify
        calls = []

        def verify(stage, files, *args, **kwargs):
            result = real(stage, files, *args, **kwargs)
            if not calls:
                calls.append(stage)
                mutate(stage)
            return result
        with mock.patch.object(self.bb, "stage_verify", side_effect=verify):
            with self.assertRaises(self.bb.Fatal):
                self.publish()

    def test_stage_swap_after_verify_refuses_both_paths_7729(self):
        for native in (self.bb.rename_noreplace_native, None):
            with self.subTest(native=native is not None), mock.patch.object(self.bb, "rename_noreplace_native", native):
                self.dest = self.dest.with_name("swap-" + str(native is None))
                replaced = []

                def swap(stage):
                    os.rename(stage, stage.with_name(stage.name + "-saved"))
                    stage.mkdir()
                    self.forge(stage)
                    replaced.append(stage)
                self.attack(swap)
                self.assertFalse(self.dest.exists())
                self.assertEqual((replaced[0] / "a.txt").read_bytes(), FORGED["a.txt"])

    def test_matching_forged_manifest_refuses_both_paths_7729(self):
        for native in (self.bb.rename_noreplace_native, None):
            with self.subTest(native=native is not None), mock.patch.object(self.bb, "rename_noreplace_native", native):
                self.dest = self.dest.with_name("content-" + str(native is None))
                self.attack(self.forge)
                self.assertFalse(self.dest.exists())

    def test_normal_publish_preserves_shared_scratch_mode_7729(self):
        for native in (self.bb.rename_noreplace_native, None):
            with self.subTest(native=native is not None), mock.patch.object(self.bb, "rename_noreplace_native", native):
                self.dest = self.dest.with_name("cert-" + str(native is None))
                self.assertEqual(self.publish(), [MANIFEST, "a.txt"])
                self.assertEqual((self.dest / "a.txt").read_bytes(), ORIGINAL["a.txt"])
                self.assertEqual((self.dest / MANIFEST).read_text(), self.manifest)
                self.assertEqual(stat.S_IMODE(self.scratch.stat().st_mode), 0o775)

    def test_destination_appears_preserved_both_paths_7729(self):
        for native in (self.bb.rename_noreplace_native, None):
            with self.subTest(native=native is not None), mock.patch.object(self.bb, "rename_noreplace_native", native):
                self.dest = self.dest.with_name("race-" + str(native is None))

                def appear(_stage):
                    self.dest.mkdir(parents=True)
                    self.forge(self.dest)
                self.attack(appear)
                self.assertEqual((self.dest / "a.txt").read_bytes(), FORGED["a.txt"])
