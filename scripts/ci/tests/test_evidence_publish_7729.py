#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Builder identity and expected-content regressions for issue #7729."""
import os
import errno
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

    def test_stage_created_inside_private_parent_7729(self):
        real = self.bb.stage_write

        def inspect(stage, *args, **kwargs):
            self.assertEqual(stat.S_IMODE(stage.parent.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(stage.stat().st_mode), 0o700)
            return real(stage, *args, **kwargs)
        with mock.patch.object(self.bb, "stage_write", side_effect=inspect):
            self.publish()

    def test_private_parent_swap_preserves_foreign_data_7729(self):
        replacement = []

        def swap(stage):
            parent = stage.parent
            os.rename(parent, parent.with_name(parent.name + "-saved"))
            stage.mkdir(parents=True)
            self.forge(stage)
            replacement.append(stage)
        self.attack(swap)
        self.assertFalse(self.dest.exists())
        self.assertEqual((replacement[0] / "a.txt").read_bytes(), FORGED["a.txt"])

    def test_missing_extra_and_symlink_refused_7729(self):
        for kind in ("missing", "extra", "symlink"):
            with self.subTest(kind=kind):
                target = self.dir / (kind + "-foreign")
                target.write_bytes(b"keep foreign bytes")

                def mutate(stage):
                    if kind == "extra":
                        (stage / "extra.txt").write_bytes(b"keep unknown bytes")
                    else:
                        (stage / "a.txt").unlink()
                        if kind == "symlink":
                            (stage / "a.txt").symlink_to(target)
                self.attack(mutate)
                self.assertFalse(self.dest.exists())
                self.assertEqual(target.read_bytes(), b"keep foreign bytes")

    def test_foreign_file_owner_refused_7729(self):
        real_stat = os.fstat
        seen = []

        def foreign(fd):
            info = real_stat(fd)
            if seen and stat.S_ISREG(info.st_mode):
                values = list(info)
                values[4] = os.geteuid() + 1
                return os.stat_result(values)
            return info
        with mock.patch.object(os, "fstat", side_effect=foreign):
            self.attack(lambda _stage: seen.append(True))
        self.assertFalse(self.dest.exists())

    def test_stage_directory_mode_refused_7729(self):
        self.attack(lambda stage: stage.chmod(0o775))
        self.assertFalse(self.dest.exists())

    def test_postpublication_mutation_is_quarantined_both_paths_7729(self):
        real = self.bb.rename_noreplace
        for native in (self.bb.rename_noreplace_native, None):
            with self.subTest(native=native is not None), mock.patch.object(self.bb, "rename_noreplace_native", native):

                def tamper(*args, **kwargs):
                    real(*args, **kwargs)
                    self.forge(self.dest)
                with mock.patch.object(self.bb, "rename_noreplace", side_effect=tamper):
                    with self.assertRaises(self.bb.Fatal):
                        self.publish()
                self.assertFalse(self.dest.exists())

    def test_postpublication_foreign_replacement_survives_7729(self):
        real = self.bb.rename_noreplace

        def replace(*args, **kwargs):
            real(*args, **kwargs)
            os.rename(self.dest, self.dest.with_name("published-saved"))
            self.dest.mkdir()
            self.forge(self.dest)
        with mock.patch.object(self.bb, "rename_noreplace", side_effect=replace):
            with self.assertRaises(self.bb.Fatal):
                self.publish()
        self.assertEqual((self.dest / "a.txt").read_bytes(), FORGED["a.txt"])

    def test_destination_parent_swap_uses_held_parent_and_rolls_back_7729(self):
        real = self.bb.rename_noreplace
        saved = self.dest.parent.with_name("evidence-saved")

        def replace(*args, **kwargs):
            os.rename(self.dest.parent, saved)
            self.dest.parent.mkdir()
            marker = self.dest.parent / "foreign.txt"
            marker.write_bytes(b"keep parent data")
            real(*args, **kwargs)
        with mock.patch.object(self.bb, "rename_noreplace", side_effect=replace):
            with self.assertRaises(self.bb.Fatal):
                self.publish()
        self.assertFalse((saved / self.dest.name).exists())
        self.assertFalse(self.dest.exists())
        self.assertEqual((self.dest.parent / "foreign.txt").read_bytes(), b"keep parent data")

    def test_destination_exists_preserved_both_paths_7729(self):
        self.dest.mkdir(parents=True)
        self.forge(self.dest)
        for native in (self.bb.rename_noreplace_native, None):
            with self.subTest(native=native is not None), mock.patch.object(self.bb, "rename_noreplace_native", native):
                with self.assertRaises(self.bb.Fatal):
                    self.publish()
                self.assertEqual((self.dest / "a.txt").read_bytes(), FORGED["a.txt"])

    def test_destination_ancestor_symlink_refused_7729(self):
        target = self.wt / "foreign"
        target.mkdir()
        (self.wt / "evidence").symlink_to(target, target_is_directory=True)
        with self.assertRaises(self.bb.Fatal):
            self.publish()
        self.assertEqual(list(target.iterdir()), [])

    def test_scratch_swap_before_writes_cannot_redirect_bytes_7729(self):
        real = self.bb.stage_write
        replacement = []

        def swap(stage, *args, **kwargs):
            os.rename(self.scratch, self.wt / "scratch-saved")
            stage.mkdir(parents=True)
            self.forge(stage)
            replacement.append(stage)
            return real(stage, *args, **kwargs)
        with mock.patch.object(self.bb, "stage_write", side_effect=swap):
            with self.assertRaises(self.bb.Fatal):
                self.publish()
        self.assertFalse(self.dest.exists())
        self.assertEqual((replacement[0] / "a.txt").read_bytes(), FORGED["a.txt"])

    def test_foreign_destination_after_failed_fallback_survives_7729(self):
        real = self.bb.stage_write

        def race(stage, *args, **kwargs):
            if stage == self.dest:
                os.rename(self.dest, self.dest.with_name("reservation-saved"))
                self.dest.mkdir()
                self.forge(self.dest)
                raise OSError("simulated population failure")
            return real(stage, *args, **kwargs)
        with mock.patch.object(self.bb, "rename_noreplace_native", None), \
                mock.patch.object(self.bb, "stage_write", race):
            with self.assertRaises(self.bb.Fatal):
                self.publish()
        self.assertEqual((self.dest / "a.txt").read_bytes(), FORGED["a.txt"])

    def test_descriptor_lifetime_on_failures_7729(self):
        real = os.open
        opened = []

        def record(*args, **kwargs):
            fd = real(*args, **kwargs)
            opened.append(fd)
            return fd
        with mock.patch.object(os, "open", side_effect=record):
            self.attack(self.forge)
        for fd in opened:
            with self.assertRaises(OSError):
                os.fstat(fd)

    def test_shared_output_parent_native_preserves_mode_7729(self):
        if self.bb.rename_noreplace_native is None:
            self.skipTest("atomic no-replace rename unavailable")
        self.dest.parent.mkdir()
        self.dest.parent.chmod(0o775)
        self.publish()
        self.assertEqual((self.dest / "a.txt").read_bytes(), ORIGINAL["a.txt"])
        self.assertEqual(stat.S_IMODE(self.dest.parent.stat().st_mode), 0o775)

    def test_shared_output_parent_fallback_preserves_mode_and_data_7729(self):
        self.dest.parent.mkdir()
        self.dest.parent.chmod(0o775)
        marker = self.dest.parent / "foreign.txt"
        marker.write_bytes(b"preserve")
        for native in (None, mock.Mock(side_effect=OSError(errno.ENOSYS, "unavailable")),
                       mock.Mock(side_effect=OSError(errno.ENOTSUP, "unsupported"))):
            with self.subTest(native=native), mock.patch.object(self.bb, "rename_noreplace_native", native):
                self.dest = self.dest.with_name(self.dest.name + "-next")
                self.publish()
                self.assertEqual((self.dest / "a.txt").read_bytes(), ORIGINAL["a.txt"])
                self.assertEqual(marker.read_bytes(), b"preserve")
                self.assertEqual(stat.S_IMODE(self.dest.parent.stat().st_mode), 0o775)
                self.assertEqual(stat.S_IMODE(self.scratch.stat().st_mode), 0o775)

    def test_portable_claim_is_private_until_fully_verified_7729(self):
        real_write, real_verify = self.bb.stage_write, self.bb.stage_verify
        observed = []

        def write(stage, *args, **kwargs):
            if stage == self.dest:
                self.assertTrue(self.dest.is_dir())
                self.assertEqual(list(self.dest.iterdir()), [])
                self.assertEqual(stat.S_IMODE(self.dest.stat().st_mode), 0o700)
                observed.append("empty-private-claim")
            return real_write(stage, *args, **kwargs)

        def verify(stage, *args, **kwargs):
            if stage == self.dest:
                self.assertEqual(stat.S_IMODE(self.dest.stat().st_mode), 0o700)
                observed.append("full-private-claim")
            return real_verify(stage, *args, **kwargs)
        with mock.patch.object(self.bb, "rename_noreplace_native", None), \
                mock.patch.object(self.bb, "stage_write", write), mock.patch.object(self.bb, "stage_verify", verify):
            self.publish()
        self.assertEqual(observed, ["empty-private-claim", "full-private-claim"])
        self.assertEqual(stat.S_IMODE(self.dest.stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE((self.dest / MANIFEST).stat().st_mode), 0o644)

    def test_portable_claim_swap_does_not_redirect_writes_7729(self):
        real = self.bb.stage_write

        def swap(stage, *args, **kwargs):
            if stage == self.dest:
                os.rename(stage, stage.with_name("claim-saved"))
                stage.mkdir()
                self.forge(stage)
            return real(stage, *args, **kwargs)
        with mock.patch.object(self.bb, "rename_noreplace_native", None), mock.patch.object(self.bb, "stage_write", swap):
            with self.assertRaises(self.bb.Fatal):
                self.publish()
        self.assertEqual((self.dest / "a.txt").read_bytes(), FORGED["a.txt"])
        self.assertEqual(list(self.dest.with_name("claim-saved").iterdir()), [])

    def test_portable_partial_write_failure_removes_only_owned_claim_7729(self):
        real = self.bb.stage_write

        def fail(stage, files, manifest, **kwargs):
            if stage == self.dest:
                real(stage, files, manifest, **kwargs)
                raise OSError(errno.ENOSPC, "simulated flush failure")
            return real(stage, files, manifest, **kwargs)
        with mock.patch.object(self.bb, "rename_noreplace_native", None), mock.patch.object(self.bb, "stage_write", fail):
            with self.assertRaises(self.bb.Fatal):
                self.publish()
        self.assertFalse(self.dest.exists())
        self.assertEqual(list(self.scratch.iterdir()), [])

    def test_executable_modes_and_manifest_bytes_both_paths_7729(self):
        files = {**ORIGINAL, "recapture.py": b"# fixture only\n"}
        manifest = self.bb.manifest_text(files)
        for native in (self.bb.rename_noreplace_native, None):
            with self.subTest(native=native is not None), mock.patch.object(self.bb, "rename_noreplace_native", native):
                self.dest = self.dest.with_name("mode-" + str(native is None))
                self.bb.publish_bundle(self.wt, self.dest, files, manifest)
                self.assertEqual((self.dest / MANIFEST).read_bytes(), manifest.encode())
                self.assertEqual((self.dest / "recapture.py").read_bytes(), files["recapture.py"])
                self.assertEqual(stat.S_IMODE((self.dest / "recapture.py").stat().st_mode), 0o755)
                self.assertEqual(stat.S_IMODE((self.dest / "a.txt").stat().st_mode), 0o644)
