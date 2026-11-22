"""Tests of deploy/docker-1461/provision/apply_age_patch.py (#9965).

The certified Apache AGE build is the pinned PG19 branch commit plus exactly one
upstream commit (apache/age 06ce678d, #2580/#2581). Every builder runs the
applier between checkout and make, and again with --verify after make. These
tests drive the script as a subprocess against a throwaway git repository that
holds a fixture ag_catalog.c, a fixture SSOT and a fixture patch, so no AGE
source and no network are needed. Every refusal is asserted by its exact exit
code and message; a tampered tree is refused by --verify.
"""
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "deploy" / "docker-1461" / "provision" / "apply_age_patch.py"
UPSTREAM = "06ce678d74210539705c77e2dc7c9fa861e2a331"
PATCH_NAME = "age-2580-06ce678d.patch"
TARGET = "src/backend/catalog/ag_catalog.c"

# Written out by hand: the shape of the function at the pinned commit, and the
# same function with the upstream guard.
ORIGINAL = """#include "postgres.h"

bool
is_age_extension_exists(void)
{
    static bool callback_registered = false;

    if (extension_cache_is_valid)
        return age_extension_exists;

    return age_extension_exists;
}
"""
GUARDED = ORIGINAL.replace(
    "    static bool callback_registered = false;\n\n",
    "    static bool callback_registered = false;\n\n"
    "    /*\n     * Outside a live transaction the catalog must not be read.\n     */\n"
    "    if (!IsTransactionState())\n        return false;\n\n",
)
# A patch that applies cleanly but adds something other than the guard.
UNGUARDED = ORIGINAL.replace(
    "    static bool callback_registered = false;\n\n",
    "    static bool callback_registered = false;\n\n    /* no guard */\n\n",
)
HEADER = f"From {UPSTREAM} Mon Sep 17 00:00:00 2001\nSubject: [PATCH] fixture\n\n---\n"


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def git(repo, *args):
    env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.invalid",
               GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.invalid", GIT_CONFIG_GLOBAL=os.devnull,
               GIT_CONFIG_NOSYSTEM="1")
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, check=True, env=env)


class ApplyAgePatchTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.src = self.base / "age"
        self.make_repo(ORIGINAL)
        self.provision = self.base / "provision"
        (self.provision / "patches").mkdir(parents=True)
        self.patch = self.provision / "patches" / PATCH_NAME
        self.ssot = self.provision / "lib.sh"
        self.write_patch(GUARDED)

    def tearDown(self):
        self.tmp.cleanup()

    def make_repo(self, content):
        if self.src.exists():
            shutil.rmtree(self.src)
        (self.src / TARGET).parent.mkdir(parents=True)
        git(self.src, "init", "-q")
        (self.src / TARGET).write_text(content)
        git(self.src, "add", TARGET)
        git(self.src, "commit", "-q", "-m", "fixture")
        self.head = git(self.src, "rev-parse", "HEAD").stdout.strip()

    def write_patch(self, patched, header=HEADER, pins=None):
        (self.src / TARGET).write_text(patched)
        diff = git(self.src, "diff", "--full-index").stdout
        git(self.src, "checkout", "-q", "--", TARGET)
        self.patch.write_text(header + diff)
        self.pins = {
            "AGE_SOURCE_COMMIT": self.head,
            "AGE_PATCH_UPSTREAM_COMMIT": UPSTREAM,
            "AGE_PATCH_FILE": PATCH_NAME,
            "AGE_PATCH_SHA256": sha256(self.patch.read_bytes()),
            "AGE_PATCHED_FILE_SHA256": sha256(patched.encode()),
        }
        self.pins.update(pins or {})
        self.write_ssot(self.pins)

    def write_ssot(self, pins, extra=""):
        body = "".join(f'{k}="${{DOCKER_1461_{k}:-{v}}}"\n' for k, v in pins.items())
        self.ssot.write_text("# fixture SSOT\n" + body + extra)

    def run_script(self, *extra):
        argv = [sys.executable, "-I", str(SCRIPT), "--ssot", str(self.ssot), "--src", str(self.src), *extra]
        return subprocess.run(argv, capture_output=True, text=True, check=False, timeout=120)

    def assert_refused(self, r, code, message):
        self.assertEqual((r.returncode, r.stdout, r.stderr), (code, "", f"apply_age_patch: {message}\n"))

    def provenance(self, verb):
        return (f"age-patch: {verb} {PATCH_NAME} (upstream apache/age {UPSTREAM}, sha256 "
                f"{self.pins['AGE_PATCH_SHA256']}) onto {self.head}; patched ag_catalog.c sha256 "
                f"{self.pins['AGE_PATCHED_FILE_SHA256']}\n")

    def test_applies_the_fix_and_prints_the_provenance_line_9965(self):
        r = self.run_script()
        self.assertEqual((r.returncode, r.stdout, r.stderr), (0, self.provenance("applied"), ""))
        self.assertEqual((self.src / TARGET).read_text(), GUARDED)
        r = self.run_script("--verify")
        self.assertEqual((r.returncode, r.stdout, r.stderr), (0, self.provenance("verified"), ""))

    def test_verify_refuses_an_unpatched_tree_9965(self):
        r = self.run_script("--verify")
        self.assert_refused(r, 6, f"{TARGET} lacks the IsTransactionState() guard of upstream {UPSTREAM}")

    def test_verify_refuses_a_tampered_tree_9965(self):
        self.assertEqual(self.run_script().returncode, 0)
        tampered = GUARDED.replace("return age_extension_exists;\n}", "return true;\n}")
        (self.src / TARGET).write_text(tampered)
        r = self.run_script("--verify")
        self.assert_refused(r, 6, f"{TARGET} sha256 {sha256(tampered.encode())} is not AGE_PATCHED_FILE_SHA256 "
                                  f"{self.pins['AGE_PATCHED_FILE_SHA256']}")
        # A guard rewritten in another form (a different condition) is not the upstream guard.
        (self.src / TARGET).write_text(GUARDED.replace("!IsTransactionState()", "!IsTransactionBlock()"))
        r = self.run_script("--verify")
        self.assert_refused(r, 6, f"{TARGET} lacks the IsTransactionState() guard of upstream {UPSTREAM}")

    def test_refuses_a_checkout_at_another_commit_9965(self):
        other = "0" * 40
        self.write_ssot(dict(self.pins, AGE_SOURCE_COMMIT=other))
        r = self.run_script()
        self.assert_refused(r, 3, f"AGE checkout is at {self.head}, not AGE_SOURCE_COMMIT {other}")
        self.assertEqual((self.src / TARGET).read_text(), ORIGINAL)

    def test_refuses_a_source_that_is_not_a_git_checkout_9965(self):
        plain = self.base / "plain"
        plain.mkdir()
        r = subprocess.run([sys.executable, "-I", str(SCRIPT), "--ssot", str(self.ssot), "--src", str(plain)],
                           capture_output=True, text=True, check=False, timeout=120,
                           env=dict(os.environ, GIT_CEILING_DIRECTORIES=str(self.base)))
        self.assert_refused(r, 3, f"AGE checkout is at no commit, not AGE_SOURCE_COMMIT {self.head}")

    def test_refuses_a_patch_whose_bytes_differ_from_the_pin_9965(self):
        data = self.patch.read_bytes() + b"\n"
        self.patch.write_bytes(data)
        r = self.run_script()
        self.assert_refused(r, 4, f"patch {PATCH_NAME} sha256 {sha256(data)} is not AGE_PATCH_SHA256 "
                                  f"{self.pins['AGE_PATCH_SHA256']}")
        self.assertEqual((self.src / TARGET).read_text(), ORIGINAL)

    def test_refuses_a_patch_from_another_upstream_commit_9965(self):
        other = "1" * 40
        self.write_patch(GUARDED, header=HEADER.replace(UPSTREAM, other))
        r = self.run_script()
        self.assert_refused(r, 4, f"patch {PATCH_NAME} does not open with upstream commit {UPSTREAM}")

    def test_refuses_a_missing_patch_file_9965(self):
        self.patch.unlink()
        r = self.run_script()
        self.assert_refused(r, 4, f"patch {PATCH_NAME} is unreadable (FileNotFoundError)")

    def test_refuses_a_patch_that_applies_only_at_an_offset_9965(self):
        self.write_patch(GUARDED)
        pins = dict(self.pins)
        self.make_repo("/* moved */\n" * 4 + ORIGINAL)
        self.pins = dict(pins, AGE_SOURCE_COMMIT=self.head)
        self.write_ssot(self.pins)
        r = self.run_script()
        self.assert_refused(r, 5, f"patch {PATCH_NAME} does not apply exactly onto {self.head} (exit 0)")
        self.assertEqual((self.src / TARGET).read_text(), "/* moved */\n" * 4 + ORIGINAL)

    def test_refuses_a_patch_that_does_not_apply_9965(self):
        self.write_patch(GUARDED)
        pins = dict(self.pins)
        changed = ORIGINAL.replace("static bool callback_registered = false;", "static int registered = 0;")
        self.make_repo(changed)
        self.pins = dict(pins, AGE_SOURCE_COMMIT=self.head)
        self.write_ssot(self.pins)
        r = self.run_script()
        self.assert_refused(r, 5, f"patch {PATCH_NAME} does not apply exactly onto {self.head} (exit 1)")
        self.assertEqual((self.src / TARGET).read_text(), changed)

    def test_refuses_a_pinned_patch_without_the_guard_9965(self):
        self.write_patch(UNGUARDED)
        r = self.run_script()
        self.assert_refused(r, 6, f"{TARGET} lacks the IsTransactionState() guard of upstream {UPSTREAM}")

    def test_refuses_bad_pins_9965(self):
        shapes = {
            "AGE_SOURCE_COMMIT": r"[0-9a-f]{40}",
            "AGE_PATCH_UPSTREAM_COMMIT": r"[0-9a-f]{40}",
            "AGE_PATCH_FILE": r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.patch",
            "AGE_PATCH_SHA256": r"[0-9a-f]{64}",
            "AGE_PATCHED_FILE_SHA256": r"[0-9a-f]{64}",
        }
        bad_values = {
            "AGE_SOURCE_COMMIT": ["c6b043d", "C6B043D1C8F4909331B9080D6640B487782FC958", ""],
            "AGE_PATCH_UPSTREAM_COMMIT": ["06ce678d", "g" * 40],
            "AGE_PATCH_FILE": ["../lib.patch", "/etc/x.patch", "x.diff", ".hidden.patch", "a/b.patch"],
            "AGE_PATCH_SHA256": ["0" * 63, "Z" * 64],
            "AGE_PATCHED_FILE_SHA256": ["", "0" * 65],
        }
        for key, values in bad_values.items():
            for value in values:
                with self.subTest(key=key, value=value):
                    self.write_ssot(dict(self.pins, **{key: value}))
                    r = self.run_script()
                    self.assert_refused(r, 2, f"pin {key} is not set exactly once in the shape {shapes[key]} "
                                              f"in {self.ssot}")
            with self.subTest(key=key, case="missing"):
                self.write_ssot({k: v for k, v in self.pins.items() if k != key})
                self.assert_refused(self.run_script(), 2, f"pin {key} is not set exactly once in the shape "
                                                          f"{shapes[key]} in {self.ssot}")
            with self.subTest(key=key, case="repeated"):
                self.write_ssot(self.pins, extra=f'{key}="${{DOCKER_1461_{key}:-{self.pins[key]}}}"\n')
                self.assert_refused(self.run_script(), 2, f"pin {key} is not set exactly once in the shape "
                                                          f"{shapes[key]} in {self.ssot}")
        self.assertEqual((self.src / TARGET).read_text(), ORIGINAL)

    def test_refuses_an_unreadable_ssot_and_a_source_that_is_not_a_directory_9965(self):
        missing = self.base / "absent.sh"
        r = subprocess.run([sys.executable, "-I", str(SCRIPT), "--ssot", str(missing), "--src", str(self.src)],
                           capture_output=True, text=True, check=False, timeout=120)
        self.assert_refused(r, 2, f"SSOT {missing} is unreadable (FileNotFoundError)")
        self.ssot.write_bytes(b"\xff\xfe")
        self.assert_refused(self.run_script(), 2, f"SSOT {self.ssot} is unreadable (UnicodeDecodeError)")
        self.write_ssot(self.pins)
        not_dir = self.base / "file"
        not_dir.write_text("x")
        r = subprocess.run([sys.executable, "-I", str(SCRIPT), "--ssot", str(self.ssot), "--src", str(not_dir)],
                           capture_output=True, text=True, check=False, timeout=120)
        self.assert_refused(r, 2, f"source directory {not_dir} is not a directory")


if __name__ == "__main__":
    unittest.main()
