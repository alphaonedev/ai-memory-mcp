"""Tests of deploy/docker-1461/provision/apply_age_patch.py and gen_age_patch.py (#9965, #9982, #9983).

The certified Apache AGE build is the pinned PG19 branch commit plus exactly one
upstream commit (apache/age 06ce678d, #2580/#2581). Every builder runs the
applier between checkout and make, and again with --verify after make. These
tests drive the scripts as subprocesses against throwaway git repositories that
hold a fixture ag_catalog.c, a fixture SSOT and a fixture patch, so no AGE
source and no network are needed. Every refusal is asserted by its exact exit
code and message, and every refusal leaves the source tree byte-identical.

The patch file is the diff body of the upstream commit only (#9983): no mail
header. Its provenance is the pin AGE_PATCH_UPSTREAM_COMMIT, and gen_age_patch.py
writes it from that commit. The last test pins the real patch in the repository
to the real SSOT, so a one-byte change to either turns this module red.
"""
import hashlib
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
PROVISION = REPO / "deploy" / "docker-1461" / "provision"
SCRIPT = PROVISION / "apply_age_patch.py"
GENERATOR = PROVISION / "gen_age_patch.py"
REAL_SSOT = PROVISION / "lib.sh"
UPSTREAM = "06ce678d74210539705c77e2dc7c9fa861e2a331"
PATCH_NAME = "age-2580-06ce678d.patch"
TARGET = "src/backend/catalog/ag_catalog.c"
FIRST_LINE = f"diff --git a/{TARGET} b/{TARGET}"
MAX_PATCH_BYTES = 1 << 20

# Exit codes of the applier, written out by hand (not imported from the script).
EXIT_OK, EXIT_BAD_INPUT, EXIT_SOURCE_MISMATCH = 0, 2, 3
EXIT_PATCH_MISMATCH, EXIT_APPLY_FAILED, EXIT_GUARD_MISSING, EXIT_SRC_NOT_TOPLEVEL = 4, 5, 6, 7
ALL_EXIT_CODES = (EXIT_OK, EXIT_BAD_INPUT, EXIT_SOURCE_MISMATCH, EXIT_PATCH_MISMATCH, EXIT_APPLY_FAILED,
                  EXIT_GUARD_MISSING, EXIT_SRC_NOT_TOPLEVEL)

# The real patch, pinned by hand from upstream apache/age 06ce678d: its sha256
# (equal to AGE_PATCH_SHA256 in lib.sh) and its blob line (preimage..postimage).
REAL_PATCH_SHA256 = "7efe593224097d43bd6779075388e16ae793f555da0ff3c5ced951d9b906d20c"
REAL_INDEX_LINE = "index 107de370d37aebaf4f42fd084ad808df7c566231..33b087a2cdd46a7f2d949afbb8f7308b62856ac8 100644"

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
# The round-1 form of the patch file: a mail header in front of the diff.
MAIL_HEADER = f"From {UPSTREAM} Mon Sep 17 00:00:00 2001\nSubject: [PATCH] fixture\n\n---\n"
GIT_ENV = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid", "GIT_COMMITTER_NAME": "t",
           "GIT_COMMITTER_EMAIL": "t@example.invalid", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def git(repo, *args):
    env = dict(os.environ, **GIT_ENV)
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, check=True, env=env)


def tree_hash(root):
    """sha256 over every path, mode and content under root except .git."""
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root)
        if rel.parts[0] == ".git":
            continue
        st = path.lstat()
        digest.update(f"{rel}\0{stat.S_IFMT(st.st_mode)}\0".encode())
        if path.is_symlink():
            digest.update(os.readlink(path).encode())
        elif path.is_file():
            digest.update(path.read_bytes())
    return digest.hexdigest()


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

    def diff_of(self, patched):
        (self.src / TARGET).write_text(patched)
        diff = git(self.src, "diff", "--full-index").stdout
        git(self.src, "checkout", "-q", "--", TARGET)
        return diff

    def write_patch(self, patched, header="", pins=None, data=None):
        if data is None:
            data = (header + self.diff_of(patched)).encode()
        self.patch.write_bytes(data)
        self.pins = {
            "AGE_SOURCE_COMMIT": self.head,
            "AGE_PATCH_UPSTREAM_COMMIT": UPSTREAM,
            "AGE_PATCH_FILE": PATCH_NAME,
            "AGE_PATCH_SHA256": sha256(data),
            "AGE_PATCHED_FILE_SHA256": sha256(patched.encode()),
        }
        self.pins.update(pins or {})
        self.write_ssot(self.pins)

    def write_ssot(self, pins, extra=""):
        body = "".join(f'{k}="${{DOCKER_1461_{k}:-{v}}}"\n' for k, v in pins.items())
        self.ssot.write_text("# fixture SSOT\n" + body + extra)

    def run_script(self, *extra, src=None, env=None):
        argv = [sys.executable, "-I", str(SCRIPT), "--ssot", str(self.ssot), "--src", str(src or self.src), *extra]
        return subprocess.run(argv, capture_output=True, text=True, check=False, timeout=120, env=env)

    def assert_refused(self, r, code, message):
        self.assertEqual((r.returncode, r.stdout, r.stderr), (code, "", f"apply_age_patch: {message}\n"))

    def provenance(self, verb):
        return (f"age-patch: {verb} {PATCH_NAME} (upstream apache/age {UPSTREAM}, sha256 "
                f"{self.pins['AGE_PATCH_SHA256']}) onto {self.head}; patched ag_catalog.c sha256 "
                f"{self.pins['AGE_PATCHED_FILE_SHA256']}\n")

    def test_applies_the_fix_and_prints_the_provenance_line_9965(self):
        self.assertEqual(self.patch.read_text().split("\n", 1)[0], FIRST_LINE)
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
        # A patched file swapped for a symlink to the right bytes is refused, not followed.
        outside = self.base / "guarded.c"
        outside.write_text(GUARDED)
        (self.src / TARGET).unlink()
        (self.src / TARGET).symlink_to(outside)
        self.assert_refused(self.run_script("--verify"), 6, f"{TARGET} is a symlink")

    def test_refuses_a_checkout_at_another_commit_9965(self):
        other = "0" * 40
        self.write_ssot(dict(self.pins, AGE_SOURCE_COMMIT=other))
        r = self.run_script()
        self.assert_refused(r, 3, f"AGE checkout is at {self.head}, not AGE_SOURCE_COMMIT {other}")
        self.assertEqual((self.src / TARGET).read_text(), ORIGINAL)

    def test_refuses_a_source_that_is_not_a_git_checkout_9965(self):
        ceiling = dict(os.environ, GIT_CEILING_DIRECTORIES=str(self.base))
        plain = self.base / "plain"
        plain.mkdir()
        r = self.run_script(src=plain, env=ceiling)
        self.assert_refused(r, 7, f"source directory {plain} is not the toplevel of a git checkout")
        # A checkout with no commit is a toplevel but is at no commit.
        empty = self.base / "empty"
        empty.mkdir()
        git(empty, "init", "-q")
        r = self.run_script(src=empty, env=ceiling)
        self.assert_refused(r, 3, f"AGE checkout is at no commit, not AGE_SOURCE_COMMIT {self.head}")

    def test_refuses_a_source_that_is_not_the_checkout_toplevel_9982(self):
        for sub in (self.src / "src", self.src / "src" / "backend" / "catalog"):
            with self.subTest(sub=sub):
                before = tree_hash(self.src)
                r = self.run_script(src=sub)
                self.assert_refused(r, 7, f"source directory {sub} is not the toplevel of a git checkout")
                self.assertEqual(tree_hash(self.src), before)
        # The toplevel check runs before the pins are read: a broken SSOT still gets exit 7.
        self.ssot.write_bytes(b"\xff")
        sub = self.src / "src"
        self.assert_refused(self.run_script(src=sub), 7,
                            f"source directory {sub} is not the toplevel of a git checkout")

    def test_refuses_a_patch_whose_bytes_differ_from_the_pin_9965(self):
        data = self.patch.read_bytes() + b"\n"
        self.patch.write_bytes(data)
        r = self.run_script()
        self.assert_refused(r, 4, f"patch {PATCH_NAME} sha256 {sha256(data)} is not AGE_PATCH_SHA256 "
                                  f"{self.pins['AGE_PATCH_SHA256']}")
        self.assertEqual((self.src / TARGET).read_text(), ORIGINAL)

    def test_refuses_a_patch_from_another_upstream_commit_9965(self):
        # The round-1 mail form (a header naming another upstream commit) is not
        # the body-only diff, even when its sha256 is pinned.
        other = "1" * 40
        self.write_patch(GUARDED, header=MAIL_HEADER.replace(UPSTREAM, other))
        r = self.run_script()
        self.assert_refused(r, 4, f"patch {PATCH_NAME} does not open with {FIRST_LINE}")
        self.write_patch(GUARDED, header=MAIL_HEADER)
        self.assert_refused(self.run_script(), 4, f"patch {PATCH_NAME} does not open with {FIRST_LINE}")
        self.assertEqual((self.src / TARGET).read_text(), ORIGINAL)

    def test_refuses_a_patch_of_any_other_file_9983(self):
        other = "src/backend/other.c"
        extra = f"diff --git a/{other} b/{other}\nnew file mode 100644\n--- /dev/null\n+++ b/{other}\n@@ -0,0 +1 @@\n+x\n"
        diff = self.diff_of(GUARDED)
        rows = (
            ("second file after", diff + extra, f"patch {PATCH_NAME} changes a file other than {TARGET}"),
            ("other file first", extra + diff, f"patch {PATCH_NAME} does not open with {FIRST_LINE}"),
            ("renamed target", diff.replace(f" b/{TARGET}", f" b/{TARGET}x", 1),
             f"patch {PATCH_NAME} does not open with {FIRST_LINE}"),
            ("empty", "", f"patch {PATCH_NAME} does not open with {FIRST_LINE}"),
        )
        for name, text, message in rows:
            with self.subTest(row=name):
                self.write_patch(GUARDED, data=text.encode())
                before = tree_hash(self.src)
                self.assert_refused(self.run_script(), 4, message)
                self.assertEqual(tree_hash(self.src), before)

    def test_refuses_a_missing_patch_file_9965(self):
        self.patch.unlink()
        r = self.run_script()
        self.assert_refused(r, 4, f"patch {PATCH_NAME} is unreadable (FileNotFoundError)")

    def test_refuses_a_patch_that_is_not_a_plain_file_in_the_patch_directory_9982(self):
        good = self.patch.read_bytes()
        outside = self.base / "outside"
        outside.mkdir()
        (outside / PATCH_NAME).write_bytes(good)

        def symlinked_file():
            self.patch.unlink()
            self.patch.symlink_to(outside / PATCH_NAME)

        def symlinked_dir():
            shutil.rmtree(self.provision / "patches")
            (self.provision / "patches").symlink_to(outside)

        def directory():
            self.patch.unlink()
            self.patch.mkdir()

        def fifo():
            self.patch.unlink()
            os.mkfifo(self.patch)

        def oversize():
            self.patch.write_bytes(b"x" * (MAX_PATCH_BYTES + 1))

        rows = (
            (symlinked_file, f"patch {PATCH_NAME} is a symlink"),
            (symlinked_dir, f"patch directory {self.provision / 'patches'} is a symlink"),
            (directory, f"patch {PATCH_NAME} is not a regular file"),
            (fifo, f"patch {PATCH_NAME} is not a regular file"),
            (oversize, f"patch {PATCH_NAME} is larger than {MAX_PATCH_BYTES} bytes"),
        )
        for make, message in rows:
            with self.subTest(row=make.__name__):
                if (self.provision / "patches").is_symlink():
                    (self.provision / "patches").unlink()
                    (self.provision / "patches").mkdir()
                if self.patch.is_dir() and not self.patch.is_symlink():
                    self.patch.rmdir()
                elif self.patch.exists() or self.patch.is_symlink():
                    self.patch.unlink()
                self.patch.write_bytes(good)
                make()
                before = tree_hash(self.src)
                self.assert_refused(self.run_script(), 4, message)
                self.assertEqual(tree_hash(self.src), before)
                self.assertEqual((self.src / TARGET).read_text(), ORIGINAL)

    def test_applies_the_bytes_it_hashed_from_stdin_9982(self):
        # A git shim on PATH records every git argv. The applier must hand
        # git apply the bytes it read and hashed (on stdin), never the path,
        # so a swap of the file after the hash cannot change what is applied.
        shim_dir = self.base / "shim"
        shim_dir.mkdir()
        log = self.base / "git-argv.log"
        real_git = shutil.which("git")
        shim = shim_dir / "git"
        shim.write_text(
            f"#!{sys.executable} -I\n"
            "import subprocess, sys\n"
            f"argv = sys.argv[1:]\n"
            f"stdin = sys.stdin.buffer.read()\n"
            f"with open({str(log)!r}, 'a') as fh:\n"
            "    fh.write(repr((argv, len(stdin), __import__('hashlib').sha256(stdin).hexdigest())) + '\\n')\n"
            f"sys.exit(subprocess.run([{real_git!r}, *argv], input=stdin).returncode)\n")
        shim.chmod(0o755)
        env = dict(os.environ, PATH=f"{shim_dir}{os.pathsep}{os.environ.get('PATH', '')}")
        r = self.run_script(env=env)
        self.assertEqual((r.returncode, r.stdout, r.stderr), (0, self.provenance("applied"), ""))
        applies = [eval(line) for line in log.read_text().splitlines() if "'apply'" in line]  # noqa: S307
        data = self.patch.read_bytes()
        argvs = [a[0][2:] for a in applies]
        self.assertEqual(argvs, [["apply", "--check", "--verbose", "-"], ["apply", "-"]])
        self.assertEqual([(a[1], a[2]) for a in applies], [(len(data), sha256(data))] * 2)
        self.assertFalse(any(str(self.patch) in " ".join(a[0]) for a in applies))

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

    def test_print_pin_prints_one_validated_pin_9984(self):
        for key, value in self.pins.items():
            with self.subTest(key=key):
                r = subprocess.run([sys.executable, "-I", str(SCRIPT), "--ssot", str(self.ssot), "--print-pin", key],
                                   capture_output=True, text=True, check=False, timeout=120)
                self.assertEqual((r.returncode, r.stdout, r.stderr), (0, value + "\n", ""))
        self.write_ssot(dict(self.pins, AGE_PATCH_FILE="../x.patch"))
        r = subprocess.run([sys.executable, "-I", str(SCRIPT), "--ssot", str(self.ssot), "--print-pin",
                            "AGE_PATCH_FILE"], capture_output=True, text=True, check=False, timeout=120)
        self.assert_refused(r, 2, "pin AGE_PATCH_FILE is not set exactly once in the shape "
                                  rf"[A-Za-z0-9][A-Za-z0-9._-]{{0,127}}\.patch in {self.ssot}")
        for argv in (["--print-pin", "NOT_A_PIN"], []):
            with self.subTest(argv=argv):
                r = subprocess.run([sys.executable, "-I", str(SCRIPT), "--ssot", str(self.ssot), *argv],
                                   capture_output=True, text=True, check=False, timeout=120)
                self.assertEqual((r.returncode, r.stdout), (2, ""))
                self.assertIn("usage: apply_age_patch.py", r.stderr)

    def test_every_exit_code_and_the_tree_it_leaves_9982(self):
        # One row per exit code, expected column written by hand: the code, and
        # whether the source tree may change (only exit 0 applies the patch).
        def ok():
            return self.src, ()

        def bad_input():
            self.ssot.write_bytes(b"\xff")
            return self.src, ()

        def source_mismatch():
            self.write_ssot(dict(self.pins, AGE_SOURCE_COMMIT="0" * 40))
            return self.src, ()

        def patch_mismatch():
            self.patch.write_bytes(self.patch.read_bytes() + b"\n")
            return self.src, ()

        def apply_failed():
            (self.src / TARGET).write_text(ORIGINAL.replace("callback_registered", "cb"))
            git(self.src, "commit", "-q", "-am", "moved")
            self.head = git(self.src, "rev-parse", "HEAD").stdout.strip()
            self.write_ssot(dict(self.pins, AGE_SOURCE_COMMIT=self.head))
            return self.src, ()

        def guard_missing():
            self.write_patch(UNGUARDED)
            return self.src, ()

        def src_not_toplevel():
            return self.src / "src", ()

        table = (
            (ok, EXIT_OK, True),
            (bad_input, EXIT_BAD_INPUT, False),
            (source_mismatch, EXIT_SOURCE_MISMATCH, False),
            (patch_mismatch, EXIT_PATCH_MISMATCH, False),
            (apply_failed, EXIT_APPLY_FAILED, False),
            (guard_missing, EXIT_GUARD_MISSING, None),
            (src_not_toplevel, EXIT_SRC_NOT_TOPLEVEL, False),
        )
        self.assertEqual(sorted(code for _, code, _ in table), sorted(ALL_EXIT_CODES))
        for make, code, changes in table:
            with self.subTest(code=code):
                self.setUp()
                try:
                    src, extra = make()
                    before = tree_hash(self.src)
                    r = self.run_script(*extra, src=src)
                    self.assertEqual(r.returncode, code, r.stderr)
                    self.assertEqual(r.stdout == "", code != EXIT_OK)
                    if changes is True:
                        self.assertNotEqual(tree_hash(self.src), before)
                        self.assertEqual((self.src / TARGET).read_text(), GUARDED)
                    elif changes is False:
                        self.assertEqual(tree_hash(self.src), before)
                    else:
                        # Exit 6 after an apply: the tree holds the applied bytes and
                        # the build stops; --verify then refuses it with the same code.
                        self.assertEqual((self.src / TARGET).read_text(), UNGUARDED)
                        self.assertEqual(self.run_script("--verify").returncode, EXIT_GUARD_MISSING)
                finally:
                    self.tearDown()
                # --verify never changes the tree, whatever the code.
                self.setUp()
                try:
                    src, extra = make()
                    before = tree_hash(self.src)
                    self.run_script("--verify", src=src)
                    self.assertEqual(tree_hash(self.src), before)
                finally:
                    self.tearDown()
        self.setUp()

    def test_the_real_patch_is_the_pinned_body_only_diff_9983(self):
        r = subprocess.run([sys.executable, "-I", str(SCRIPT), "--ssot", str(REAL_SSOT), "--print-pin",
                            "AGE_PATCH_SHA256"], capture_output=True, text=True, check=False, timeout=120)
        self.assertEqual((r.returncode, r.stderr), (0, ""))
        self.assertEqual(r.stdout, REAL_PATCH_SHA256 + "\n")
        name = subprocess.run([sys.executable, "-I", str(SCRIPT), "--ssot", str(REAL_SSOT), "--print-pin",
                               "AGE_PATCH_FILE"], capture_output=True, text=True, check=True, timeout=120).stdout
        self.assertEqual(name, PATCH_NAME + "\n")
        data = (PROVISION / "patches" / PATCH_NAME).read_bytes()
        self.assertEqual(sha256(data), REAL_PATCH_SHA256)
        lines = data.decode("ascii").split("\n")
        self.assertEqual(lines[:2], [FIRST_LINE, REAL_INDEX_LINE])
        self.assertEqual([ln for ln in lines if ln.startswith("diff --git ")], [FIRST_LINE])
        self.assertIn("+    if (!IsTransactionState())", lines)
        upstream = subprocess.run([sys.executable, "-I", str(SCRIPT), "--ssot", str(REAL_SSOT), "--print-pin",
                                   "AGE_PATCH_UPSTREAM_COMMIT"], capture_output=True, text=True, check=True,
                                  timeout=120).stdout
        self.assertEqual(upstream, UPSTREAM + "\n")


class GenAgePatchTest(unittest.TestCase):
    """gen_age_patch.py writes the body-only diff of the pinned upstream commit."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.clone = self.base / "upstream"
        (self.clone / TARGET).parent.mkdir(parents=True)
        git(self.clone, "init", "-q")
        (self.clone / TARGET).write_text(ORIGINAL)
        git(self.clone, "add", TARGET)
        git(self.clone, "commit", "-q", "-m", "root")
        self.root = git(self.clone, "rev-parse", "HEAD").stdout.strip()
        (self.clone / TARGET).write_text(GUARDED)
        git(self.clone, "commit", "-q", "-am", "the fix")
        self.fix = git(self.clone, "rev-parse", "HEAD").stdout.strip()
        (self.clone / "other.c").write_text("x\n")
        (self.clone / TARGET).write_text(GUARDED + "/* more */\n")
        git(self.clone, "add", "other.c", TARGET)
        git(self.clone, "commit", "-q", "-m", "two files")
        self.two = git(self.clone, "rev-parse", "HEAD").stdout.strip()
        self.provision = self.base / "provision"
        (self.provision / "patches").mkdir(parents=True)
        self.ssot = self.provision / "lib.sh"
        self.out = self.provision / "patches" / PATCH_NAME
        self.write_ssot(self.fix)

    def tearDown(self):
        self.tmp.cleanup()

    def write_ssot(self, upstream, source=None):
        source = self.root if source is None else source
        pins = {"AGE_SOURCE_COMMIT": source, "AGE_PATCH_UPSTREAM_COMMIT": upstream, "AGE_PATCH_FILE": PATCH_NAME,
                "AGE_PATCH_SHA256": "0" * 64, "AGE_PATCHED_FILE_SHA256": "0" * 64}
        self.ssot.write_text("".join(f'{k}="${{DOCKER_1461_{k}:-{v}}}"\n' for k, v in pins.items()))

    def run_gen(self, *extra):
        argv = [sys.executable, "-I", str(GENERATOR), "--ssot", str(self.ssot), "--age", str(self.clone), *extra]
        return subprocess.run(argv, capture_output=True, text=True, check=False, timeout=120)

    def expected_body(self, commit):
        return git(self.clone, "diff", "--full-index", f"{commit}^", commit).stdout.encode()

    def test_writes_the_body_only_diff_and_checks_it_9983(self):
        r = self.run_gen()
        body = self.expected_body(self.fix)
        self.assertEqual((r.returncode, r.stderr), (0, ""))
        self.assertEqual(r.stdout, f"gen-age-patch: wrote {PATCH_NAME} from upstream {self.fix} "
                                   f"(sha256 {sha256(body)})\n")
        self.assertEqual(self.out.read_bytes(), body)
        self.assertEqual(body.split(b"\n", 1)[0].decode(), FIRST_LINE)
        r = self.run_gen("--check")
        self.assertEqual((r.returncode, r.stdout, r.stderr),
                         (0, f"gen-age-patch: {PATCH_NAME} matches upstream {self.fix} (sha256 {sha256(body)})\n", ""))
        # One byte changed in the stored patch: --check is red.
        changed = body.replace(b"Outside", b"outside", 1)
        self.out.write_bytes(changed)
        r = self.run_gen("--check")
        self.assertEqual((r.returncode, r.stdout, r.stderr),
                         (1, "", f"gen_age_patch: patch {PATCH_NAME} sha256 {sha256(changed)} is not the diff body "
                                 f"of {self.fix} (sha256 {sha256(body)})\n"))

    def test_refuses_a_commit_that_is_not_the_one_file_fix_9983(self):
        self.write_ssot(self.two)
        r = self.run_gen()
        self.assertEqual((r.returncode, r.stdout, r.stderr),
                         (4, "", f"gen_age_patch: upstream commit {self.two} changes a file other than {TARGET}\n"))
        self.write_ssot(self.root)
        r = self.run_gen()
        self.assertEqual((r.returncode, r.stdout, r.stderr),
                         (3, "", f"gen_age_patch: upstream commit {self.root} is not a single-parent commit in "
                                 f"{self.clone}\n"))
        self.assertFalse(self.out.exists())

    def side_branch(self, name, text):
        """A source commit off the root on its own branch (the PG19 branch shape), its target set to text."""
        git(self.clone, "checkout", "-q", "-b", name, self.root)
        (self.clone / TARGET).write_text(text)
        git(self.clone, "commit", "-q", "-am", name)
        return git(self.clone, "rev-parse", "HEAD").stdout.strip()

    def test_carries_the_upstream_change_onto_the_source_commit_9983(self):
        # The source branch has lines the upstream parent lacks, so the plain
        # upstream diff would apply only at an offset. The expected body is
        # built here by hand: the guard written onto the source text, diffed.
        prefix = "/* pg19 branch */\n/* line two */\n/* line three */\n"
        source = self.side_branch("pg19", prefix + ORIGINAL)
        (self.clone / TARGET).write_text(prefix + GUARDED)
        git(self.clone, "commit", "-q", "-am", "expected")
        expected = git(self.clone, "diff", "--full-index", source, "HEAD").stdout.encode()
        git(self.clone, "reset", "-q", "--hard", source)
        self.write_ssot(self.fix, source)
        r = self.run_gen()
        self.assertEqual((r.returncode, r.stderr), (0, ""))
        self.assertEqual(self.out.read_bytes(), expected)
        self.assertNotEqual(expected, self.expected_body(self.fix), "the fixture must need the carry")
        r = self.run_gen("--check")
        self.assertEqual((r.returncode, r.stderr), (0, ""))

    def test_refuses_a_change_that_does_not_apply_onto_the_source_commit_9983(self):
        source = self.side_branch("diverged", ORIGINAL.replace("static bool callback_registered", "int other"))
        self.write_ssot(self.fix, source)
        r = self.run_gen()
        self.assertEqual((r.returncode, r.stdout, r.stderr),
                         (4, "", f"gen_age_patch: upstream commit {self.fix} does not apply onto AGE_SOURCE_COMMIT "
                                 f"{source}\n"))
        self.assertFalse(self.out.exists())
        self.assertEqual([p.name for p in Path(git(self.clone, "rev-parse", "--absolute-git-dir").stdout.strip())
                          .glob("gen-age-patch-*")], [], "the private index is removed")


if __name__ == "__main__":
    unittest.main()
