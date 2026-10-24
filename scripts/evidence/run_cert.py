#!/usr/bin/env python3
"""§7 enterprise-federation cert re-issue runner (ai:rehearsal-f2h). Python port of the certv2 shell harness.

Subcommands (every one asserts the worktree HEAD == --tip and a clean tracked tree first):
  battery    release builds (default; --no-default-features sqlcipher,sal), posture recapture (4 legs),
             8 named integration bins + 3 lib slices (default features), each via cargo-slot.py
  pg         #4434 coverage leg under --features sal-postgres (1 bin + 1 lib slice), via cargo-slot.py
  removal    scripts/check-cert-removal-proof.sh BARE under the optional --slot-lock flock, nice 15,
             ionice -c3 when installed, CARGO_BUILD_JOBS=2; writes cert-alone.out; then --force-restore and a dirty check
  bootstrap  scripts/check-bootstrap-cert-gate.sh self-build path under the same optional flock
  chain      battery; if green: removal, pg, bootstrap (each runs whatever the previous one returned)
  gates      on the CERT COMMIT (HEAD = one commit on top of --tip): the cargo-free gates, the scope gate
             (only the cert doc + its evidence dir), %G? = G; pushes --push-branch only when fails == 0

Every outcome is a line in OUTD/legs.log (the gates leg: OUTD/gates.log, #5042); each invocation starts with a CONFIG
row (the paths used and where each came from) and a PLAN row (the legs it promises) and ends with an EXIT row, so a
killed invocation is visible to build_bundle.check_run (#7437). Exit status: 0 = every leg green, 1 = a leg failed,
exit 64 = a refused configuration. A bad option or a path under a tmp root or on a tmpfs is refused before the run
exists: such refusals write nothing (stderr only). A missing wrapper, flock or timeout is refused by the preflight: the
CONFIG and PLAN rows, a `RED preflight` row and an `EXIT=64` row are written, and no leg starts. 127 = a leg command
that could not start (a RED launch row). Paths default to the checkout (.local-runs/); see the --cargo-slot/--slot-lock/--targets/--tmpdir options.
"""
import sys

# #7730: isolate direct entry before any filesystem-backed import. sys and the OS
# backend are built-ins; os itself is not frozen/cached on every Python 3.9 startup.
# This cannot undo interpreter startup hooks that ran before this script began.
if __name__ == "__main__" and not sys.flags.isolated:
    __import__("posix" if "posix" in sys.builtin_module_names else "nt").execv(
        sys.executable, [sys.executable, "-I", *sys.argv])

import argparse
import datetime
import os
import re
import shlex
import shutil
import stat
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
# Repo-relative defaults (#5040). Each is overridable by an argument or an environment variable:
#   --cargo-slot / CERT_CARGO_SLOT  optional cargo semaphore wrapper (unset: plain `cargo`)
#   --slot-lock  / CERT_SLOT_LOCK    optional flock file serialising the removal-proof and bootstrap legs (unset: no flock)
#   --targets    / CERT_TARGETS      cargo target dirs (default: <repo>/.local-runs/cert-targets)
#   --tmpdir     / CERT_TMPDIR       TMPDIR for every leg (default: <repo>/.local-runs/cert-tmp; never a tmpfs)
DEFAULT_TARGETS = REPO_ROOT / ".local-runs" / "cert-targets"
DEFAULT_TMPDIR = REPO_ROOT / ".local-runs" / "cert-tmp"
CERT_DOC = "docs/compliance/ENTERPRISE-FEDERATION-CERTIFICATION.md"
# GiB free required (statvfs f_bavail) on the build volume (holds the target dirs) and on the root volume; GOD 7caf919e.
FLOOR_BUILD_GIB = 120
FLOOR_ROOT_GIB = 60

# Batch-6 baseline (cert-385da3a05/test-results.txt). A difference is logged as COUNT_DIFF, never silently accepted.
BINS = {
    "boot_fail_closed_config_3166": 15,
    "doctor_posture_exit_code_3003": 2,
    "doctor_synchronous_posture_3553": 3,
    "federation_catchup_posture_3582": 1,
    "federation_namespace_gate_3582": 3,
    "federation_peer_posture_3582": 10,
    "federation_write_ns_scope_2447": 6,
    "posture_control15_pg_resolution_3106": 3,
}
LIBS = {"enterprise_federation_posture": 37, "federation::peer_posture": 5, "cli::backup::tests": 81}
PG_BIN = ("posture_control15_pg_resolution_3106", 4)
PG_LIB = ("enterprise_federation_posture", 39)
RESULT_RE = re.compile(r"^test result: (\w+)\. (\d+) passed; (\d+) failed", re.M)


RECAPTURE_CANDIDATES = ("scripts/recapture-cert-3607-posture.py", "scripts/recapture-cert-3607-posture.sh")
EXPIRY_PY = "scripts/check_cert_expiry.py"
# #7617 / #7618: a script of the git tree is never written to disk and run. It is read from its blob and handed to
# `python -I -c PY_LOADER <checkout path of the script>` on stdin. The loader gives the script the identity it has
# when run by path: __name__ == "__main__", __file__ the checkout path (so a REPO_ROOT derived from __file__ is the
# checkout), sys.argv[0] the same path, the script's own arguments after it.
PY_LOADER = (
    "import sys, types\n"
    "m = types.ModuleType('__main__')\n"
    "g = m.__dict__\n"
    "for k in ('__doc__', '__package__', '__loader__'):\n"
    "    g.pop(k, None)\n"
    "g['__file__'] = sys.argv[1]\n"
    "g['__builtins__'] = __builtins__\n"
    "src = sys.stdin.buffer.read()\n"
    "sys.argv = sys.argv[1:]\n"
    "sys.modules['__main__'] = m\n"
    "exec(compile(src, g['__file__'], 'exec'), g)\n"
)
# #7666: the script runs in the fresh module `m`; its globals hold exactly __name__, __spec__, __file__ and
# __builtins__, so none of the loader's own names (sys, types, m, g, src) is visible to it, and sys.modules['__main__']
# is that module, so dataclasses, pickle and typing resolve the script's own classes.
MAX_INLINE_SCRIPT = 100_000  # a shell body travels as one argv entry (the kernel limits one to 128 KiB)
SWEEP_MAX_DEPTH = 100_000  # the deepest legacy scratch tree the sweep descends into
SCRATCH_WORLD_WRITABLE = 0o002  # #7662: a group-writable directory owned by this user is accepted (umask 0002 checkouts)
# #7663 / #7665: a child never inherits the checkout as its working directory. The Python variables below would let an
# inner `python3` import from a directory the caller names or from the user site. These variables are defense in
# depth; interpreter -I below supplies the isolation on every supported Python, including 3.9 (#7728).
SCRUBBED_PYTHON_ENV = ("PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "PYTHONUSERBASE")
SAFE_PYTHON_ENV = {"PYTHONSAFEPATH": "1", "PYTHONNOUSERSITE": "1"}
SCRUBBED_SHELL_ENV = ("BASH_ENV", "ENV")
PRIVATE_EXEC_MODE = 0o500
MAX_SHEBANG_BYTES = 127  # portable kernel shebang bound, including newline
PRIVATE_DIRECTORY_MODE = 0o700
PRIVATE_DIRECTORY_ATTEMPTS = 100
PRIVATE_DIRECTORY_RANDOM_BYTES = 16
PYTHON_COMMAND = re.compile(r"python(?:3(?:\.\d+)?)?\Z")


def close_all(fds):
    """Close every descriptor; keep the first OSError and re-raise it after the loop (#7876, as #7871).

    decision: an identical small helper lives here and in build_bundle.py (which uses ExitStack) because both
    scripts run as standalone files with no shared package to import from.
    """
    first = None
    for fd in fds:
        try:
            os.close(fd)
        except OSError as e:
            if first is None:
                first = e
    if first is not None:
        raise first


def isolated_python_environment(env, launcher_dir):
    """Pin nested gate Python to this interpreter, without trusting PATH or a checkout helper.

    The existing shell gates invoke python3 by name. A private Python launcher starts under -I itself and execs
    the absolute running interpreter with -I; it never searches PATH (including its own directory). Keep the
    launcher outside the empty child cwd. No shell gate source or compiler command is rewritten.
    """
    executable = os.path.abspath(sys.executable)
    shebang = f"#!{executable} -I\n"
    if any(c.isspace() for c in executable) or len(shebang.encode()) > MAX_SHEBANG_BYTES:
        raise ConfigError("the Python executable path cannot be represented safely in a launcher shebang")
    source = (shebang + '"""Private isolated interpreter launcher (#7728)."""\n'
              + "import os, sys\n"
              + f"os.execv({executable!r}, [{executable!r}, '-I', *sys.argv[1:]])\n")
    for name in ("python", "python3", f"python{sys.version_info.major}.{sys.version_info.minor}"):
        launcher = launcher_dir / name
        with launcher.open("x") as stream:
            stream.write(source)
        launcher.chmod(PRIVATE_EXEC_MODE)
    for key in list(env):
        if key in (*SCRUBBED_PYTHON_ENV, *SCRUBBED_SHELL_ENV) or key.startswith("BASH_FUNC_"):
            env.pop(key)
    env.update(SAFE_PYTHON_ENV)
    env["PATH"] = str(launcher_dir) + os.pathsep + env.get("PATH", os.defpath)
    return env


def open_scratch(scratch, *, dir_fd=None):
    """`scratch` opened as a directory fd (O_DIRECTORY|O_NOFOLLOW), or None when it does not exist (it is never created
    here). ValueError unless it is a plain directory owned by this user that is not world writable. A group-writable
    directory is accepted: a umask-0002 checkout tracks .local-runs as 0775 (#7662). Shared by run_cert and
    build_bundle (#7668). Optional dir_fd anchors a relative name to an already checked parent (#7731)."""
    scratch = Path(scratch)
    try:
        fd = os.open(scratch, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0), dir_fd=dir_fd)
    except FileNotFoundError:
        return None
    except OSError as e:
        raise ValueError(f"{scratch} is not a plain directory ({e.strerror or e}); remove it or replace it by a "
                         "directory you own") from e
    accepted = False
    try:
        st = os.fstat(fd)
        if st.st_uid != os.geteuid():
            raise ValueError(f"{scratch} is owned by uid {st.st_uid} (this run is uid {os.geteuid()}); it must be "
                             "owned by this user")
        if st.st_mode & SCRATCH_WORLD_WRITABLE:
            raise ValueError(f"{scratch} is world writable (mode {stat.S_IMODE(st.st_mode):04o}); chmod o-w")
        accepted = True
    finally:
        if not accepted:
            os.close(fd)
    return fd
EXPIRY_SH = "scripts/check-cert-expiry.sh"
# The legs one invocation promises (the PLAN row); build_bundle.check_run holds each invocation to its plan (#7437).
PLANS = {"battery": ("battery",), "pg": ("pg",), "removal": ("removal",), "bootstrap": ("bootstrap",),
         "chain": ("battery", "removal", "pg", "bootstrap", "chain"), "gates": ("gates",)}
CARGO_LEGS = ("battery", "pg", "chain")
LOW_PRIORITY_LEGS = ("removal", "bootstrap", "chain")
# Built from parts so this script carries no tmpfs path literal (#5040).
TMP_ROOTS = tuple("/" + part for part in ("tmp", "var/tmp", "private/tmp"))


class ConfigError(Exception):
    """A CERT_* / option value the runner refuses (exit 64)."""


def anchored(p):
    """A configured path as an absolute path: relative values resolve against this checkout, never the caller's cwd
    or the gated worktree (#7421)."""
    q = Path(os.path.expanduser(str(p)))
    return q if q.is_absolute() else REPO_ROOT / q


def unescape_mount(field):
    """/proc/mounts writes space, tab, newline and backslash in a mount point as \\040, \\011, \\012, \\134 (#7442)."""
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), field)


def is_tmpfs_path(path, mounts=None):
    """True for /tmp, /var/tmp, /private/tmp and anything on a tmpfs/ramfs mount (project rule: no tmpfs scratch)."""
    p = os.path.realpath(os.path.normpath(str(path)))
    folded = p.casefold()  # a case-insensitive filesystem (macOS) reaches the same directory by another spelling (#7534)
    roots = {x.casefold() for r in TMP_ROOTS for x in (r, os.path.realpath(r))}
    if any(folded == r or folded.startswith(r.rstrip("/") + "/") for r in roots):
        return True
    if mounts is None:
        try:
            mounts = Path("/proc/mounts").read_text()
        except OSError:  # no /proc (macOS): the prefix rule above is all that can be checked
            return False
    best = None
    for line in mounts.splitlines():
        f = line.split()
        if len(f) < 3:
            continue
        mp = unescape_mount(f[1])
        if (p == mp or p.startswith(mp.rstrip("/") + "/")) and (best is None or len(mp) >= len(best[0])):
            best = (mp, f[2])
    return best is not None and best[1] in ("tmpfs", "ramfs")


def choose(arg, env_name, default):
    """(anchored value, source) for one configured path: the option, else the environment, else the default (#7441).
    An unset optional value ("" default) stays ""."""
    if arg:
        return anchored(arg), "arg"
    if os.environ.get(env_name):
        return anchored(os.environ[env_name]), "env"
    return (anchored(default) if default else ""), "default"


def run_tmpdir():
    """The TMPDIR a run uses: $CERT_TMPDIR (anchored) else the repo-local default."""
    return anchored(os.environ.get("CERT_TMPDIR") or DEFAULT_TMPDIR)


def tracked_at(wt, rev, rel):
    return subprocess.run(["git", "-C", str(wt), "cat-file", "-e", f"{rev}:{rel}"], cwd=str(wt),
                          capture_output=True).returncode == 0


def tree_entry(wt, rev, rel):
    """(mode, type, sha) of rel in rev's tree, or None when it is not tracked there."""
    r = subprocess.run(["git", "-C", str(wt), "ls-tree", rev, "--", rel], cwd=str(wt),
                       capture_output=True, text=True)
    if r.returncode != 0 or not r.stdout.strip():
        return None
    meta = r.stdout.strip().split("\t", 1)[0].split()
    return meta[0], meta[1], meta[2]


def blob_bytes(wt, rev, rel):
    """(sha, bytes) of the regular-file blob rev:rel. Never the disk copy: a skip-worktree or assume-unchanged file
    cannot stand in for it, and a symlink (mode 120000) or submodule is refused (#7439)."""
    e = tree_entry(wt, rev, rel)
    if e is None:
        raise FileNotFoundError(f"{rel} is not tracked at {rev}")
    mode, kind, sha = e
    if kind != "blob" or mode not in ("100644", "100755"):
        raise ValueError(f"{rel} at {rev} is a {kind} of mode {mode}; only a regular tracked file is run")
    return sha, subprocess.run(["git", "-C", str(wt), "cat-file", "blob", sha], cwd=str(wt),
                          capture_output=True, check=True).stdout


def pick_recapture(wt, tip):
    """The posture recapture script of the TIP TREE: the Python port first, the shell script second (#7399). An
    untracked or modified file on disk can never stand in for the tip's (#7411)."""
    for rel in RECAPTURE_CANDIDATES:
        if tracked_at(wt, tip, rel):
            return rel
    raise FileNotFoundError("no recapture script at the tip; looked for " + " then ".join(RECAPTURE_CANDIDATES))


def recapture_blob(wt, tip):
    """(relpath, source, blob sha) of the tip's recapture script, read from the tip blob, not the disk."""
    rel = pick_recapture(wt, tip)
    sha, data = blob_bytes(wt, tip, rel)
    return rel, data.decode("utf-8"), sha


def recapture_source(wt, tip):
    """(relpath, source) of the tip's recapture script."""
    rel, src, _sha = recapture_blob(wt, tip)
    return rel, src


def retarget_shell(src, ev, fix):
    """Retarget the two $ROOT-relative assignments of the shell recapture script; the values are shell-quoted (#7412)."""
    body, n_out = re.subn(r'^OUT="\$ROOT/[^"\n]*"$', lambda _m: f"OUT={shlex.quote(str(ev))}", src, flags=re.M)
    body, n_fix = re.subn(r'^FIX="\$ROOT/[^"\n]*"$', lambda _m: f"FIX={shlex.quote(str(fix))}", body, flags=re.M)
    return body, n_out, n_fix


class Run:
    def __init__(self, a):
        self.tip = a.tip
        self.wt = Path(a.wt)
        self.leg = a.leg
        self.outd = Path(a.outd)
        # #5042: the gates leg runs after the chain and writes its own artifact, so the RUN-RECORD legs-log hash and
        # the bundle builder's chain gate read the chain's rows alone.
        self.log = self.outd / ("gates.log" if a.leg == "gates" else "legs.log")
        # #7421: every configured path resolves against this checkout; #7413 / #7440: none may sit on a tmpfs.
        self.targets, src_t = choose(getattr(a, "targets", None), "CERT_TARGETS", DEFAULT_TARGETS)
        self.tmpdir, src_d = choose(getattr(a, "tmpdir", None), "CERT_TMPDIR", DEFAULT_TMPDIR)
        slot, src_s = choose(getattr(a, "cargo_slot", None), "CERT_CARGO_SLOT", "")
        lock, src_l = choose(getattr(a, "slot_lock", None), "CERT_SLOT_LOCK", "")
        self.sources = {"cargo_slot": src_s, "slot_lock": src_l, "targets": src_t, "tmpdir": src_d, "outd": "arg"}
        for what, path in (("--targets / CERT_TARGETS", self.targets), ("--tmpdir / CERT_TMPDIR", self.tmpdir),
                           ("--outd", Path(os.path.abspath(self.outd)))):
            if is_tmpfs_path(path):
                raise ConfigError(f"{what} = {path} is on a tmpfs or under a tmp root; choose a persistent disk path")
        self.cargo_slot = str(slot) if slot else ""
        self.cargo = [self.cargo_slot, "cargo"] if slot else ["cargo"]
        self.slot_lock = str(lock) if lock else ""
        os.umask(0o022)  # #7662: before the first mkdir, so every directory made here is 0755
        self.scratch_identities = {}
        for path in (self.targets, self.tmpdir):
            try:
                path.mkdir(parents=True, exist_ok=True)
            except OSError as e:
                raise ConfigError(f"{path}: cannot create scratch directory: {e}") from e
            fd = self.guarded_scratch(path)
            try:
                st = os.fstat(fd)
                self.scratch_identities[path] = (st.st_dev, st.st_ino)
            finally:
                os.close(fd)
        self.outd.mkdir(parents=True, exist_ok=True)
        self.bad = 0
        self.floor_tripped = False
        self.env = dict(os.environ)
        for k in SCRUBBED_PYTHON_ENV:
            self.env.pop(k, None)
        self.env.update(SAFE_PYTHON_ENV)
        for k in ("XDG_CONFIG_HOME", "GIT_AUTHOR_EMAIL", "GIT_COMMITTER_EMAIL", "AI_MEMORY_AGENT_ID",
                  "AI_MEMORY_BIN", "AI_MEMORY_BIN_PG", "CARGO_TARGET_DIR", "CARGO_BUILD_JOBS"):
            self.env.pop(k, None)
        self.env.update(AI_MEMORY_NO_CONFIG="1", TMPDIR=str(self.tmpdir))

    @staticmethod
    def now(fmt="%H:%MZ"):
        return datetime.datetime.now(datetime.timezone.utc).strftime(fmt)

    def note(self, line):
        with self.log.open("a") as f:
            f.write(line + "\n")
        print(line, flush=True)

    def fail(self, line):
        self.bad += 1
        self.note(line)

    def config_row(self):
        """The wrapper and paths actually used and where each came from, one row per invocation (#7413, #7441)."""
        srcs = ",".join(f"{k}:{v}" for k, v in self.sources.items())
        return (f"CONFIG cargo_slot={self.cargo_slot or 'none'} slot_lock={self.slot_lock or 'none'} "
                f"targets={self.targets} tmpdir={self.tmpdir} outd={self.outd} sources={srcs}")

    def plan_row(self, leg):
        """The legs this invocation promises; check_run holds the log to it (#7437)."""
        return f"PLAN leg={leg} legs={','.join(PLANS[leg])}"

    def preflight(self):
        """Fail closed BEFORE any leg runs when a tool the leg needs is unusable (#7441)."""
        if self.leg != "gates" and self.cargo_slot:
            w = Path(self.cargo_slot)
            if not (w.is_file() and os.access(w, os.X_OK)):
                raise ConfigError(f"--cargo-slot / CERT_CARGO_SLOT = {w} is not an executable file")
        if self.leg in LOW_PRIORITY_LEGS:
            for tool in ("timeout", "nice"):
                if not shutil.which(tool):
                    raise ConfigError(f"`{tool}` is not installed; the {self.leg} leg runs its gate script under it")
            if self.slot_lock and not shutil.which("flock"):
                raise ConfigError(f"`flock` is not installed but --slot-lock / CERT_SLOT_LOCK = {self.slot_lock} is set")

    def git(self, *args):
        return subprocess.run(["git", *args], cwd=self.wt, capture_output=True, text=True).stdout.strip()

    def dirty_tracked(self):
        return [l for l in self.git("status", "--porcelain").splitlines() if l and not l.startswith("??")]

    def assert_tree(self, head, tag):
        h = self.git("rev-parse", "HEAD")
        if h != head or self.dirty_tracked():
            self.fail(f"{tag} WRONG-HEAD/DIRTY head={h} want={head} dirty={len(self.dirty_tracked())}")
            return False
        return True

    def floor_ok(self, what):
        """GOD 7caf919e: df before each Run.run command with gate=True (the default); force-restore and gate checks bypass it with gate=False. Once tripped, gated commands stop."""
        if self.floor_tripped:
            return False
        for mount, floor in ((self.targets, FLOOR_BUILD_GIB), (Path("/"), FLOOR_ROOT_GIB)):
            st = os.statvfs(mount)
            free = st.f_bavail * st.f_frsize / 2**30
            if free < floor:
                self.floor_tripped = True
                self.fail(f"DISK-FLOOR STOP {mount} free={free:.1f}GiB < {floor} before {what} {self.now()}")
                return False
        return True

    def run(self, argv, out, extra_env=None, cwd=None, gate=True, stdin_data=None):
        """Run argv with stdout and stderr in `out`. stdin_data (bytes) is the child's stdin; without it stdin is empty.
        The child's working directory is a fresh empty 0700 directory under the tmpdir, removed afterwards, unless the
        caller names `cwd` (#7663: only the cargo legs do, for the checkout's rust-toolchain.toml)."""
        if gate and not self.floor_ok(" ".join(map(str, argv))[:120]):
            Path(out).write_text("NOT RUN: disk floor tripped\n")
            return 75
        env = dict(self.env)
        env.update(extra_env or {})
        roots = {}
        opened_roots = []  # (path, fd) pairs, the closing loop below owns every descriptor
        private = []
        try:
            # #7731: reapply the shared policy at use and bind mkdir/cleanup to the checked root.
            for path in (self.targets, self.tmpdir):
                if path not in roots:
                    root_path, root_fd = self.guarded_root(path)
                    opened_roots.append((root_path, root_fd))
                    roots[root_path] = root_fd
            scratch_fd = roots[self.tmpdir]
            launcher_name, launcher_fd = self.private_directory(scratch_fd, "python-")
            private.append((launcher_name, launcher_fd))
            launcher_dir = self.tmpdir / launcher_name
            self.check_scratch_paths(roots, private)
            env = isolated_python_environment(env, launcher_dir)
            # Direct Python calls also use the selected interpreter, even if a caller supplies another PATH name.
            if PYTHON_COMMAND.fullmatch(Path(str(argv[0])).name) or str(argv[0]) == sys.executable:
                argv = [sys.executable, "-I", *argv[1:]]
            box = None
            if cwd is None:
                name, fd = self.private_directory(scratch_fd, "child-")
                private.append((name, fd))
                box = self.tmpdir / name
            # subprocess cwd and launcher lookup remain portable path operations. This check detects replacements
            # before launch; it is not atomic against concurrent renames by the owner or an accepted group.
            self.check_scratch_paths(roots, private)
            with open(out, "wb") as f:
                feed = {"input": stdin_data} if stdin_data is not None else {"stdin": subprocess.DEVNULL}
                return subprocess.run(argv, cwd=str(box or cwd), env=env, stdout=f, stderr=subprocess.STDOUT,
                                      **feed).returncode
        except OSError as e:  # a missing wrapper, flock or timeout (#7420): a RED row and 127, never a traceback
            print(f"run_cert: cannot start {argv[0]!r}: {e.strerror or e}. Check that --cargo-slot / CERT_CARGO_SLOT "
                  "names an executable wrapper and that flock, nice and timeout are installed.", file=sys.stderr)
            Path(out).write_text(f"NOT RUN: cannot start {argv[0]}: {e}\n")
            self.fail(f"  RED launch {argv[0]}: {e.strerror or e}")
            return 127
        finally:
            try:
                for name, fd in reversed(private):
                    try:
                        seen = os.stat(name, dir_fd=roots[self.tmpdir], follow_symlinks=False)
                        owned = os.fstat(fd)
                        if (seen.st_dev, seen.st_ino) != (owned.st_dev, owned.st_ino):
                            raise ValueError(f"{name} was replaced; left in place")
                        self.remove_tree(roots[self.tmpdir], name, expected_identity=(owned.st_dev, owned.st_ino))
                    except (OSError, ValueError) as e:
                        self.fail(f"  RED private scratch cleanup: {e}")
            finally:
                # #7876: one failing close must not leak the rest; private directories close before the roots.
                close_all([fd for _name, fd in reversed(private)] + [fd for _path, fd in opened_roots])

    def guarded_root(self, path):
        """(path, descriptor) of a guarded scratch root: the pair form run() records and closes in its finally."""
        return path, self.guarded_scratch(path)

    def guarded_scratch(self, path):
        """Open a configured root through the shared policy, refusing removal or replacement since setup."""
        try:
            fd = open_scratch(path)
        except ValueError as e:
            raise ConfigError(str(e)) from e
        if fd is None:
            raise ConfigError(f"{path}: scratch directory disappeared")
        try:  # #7870: ownership passes to the caller only after validation; any failure closes the descriptor here
            st = os.fstat(fd)
            expected = self.scratch_identities.get(path)
            if expected is not None and (st.st_dev, st.st_ino) != expected:
                raise ConfigError(f"{path}: scratch directory was replaced")
        except BaseException:
            os.close(fd)
            raise
        return fd

    @staticmethod
    def remove_empty_private(scratch_fd, name):
        """Best-effort removal of the empty directory `name` this run just created (#8211). The entry is checked with a
        no-follow stat (a directory owned by this user) and removed with rmdir, so a symlink or a replacement planted
        at the path is left alone; rmdir fails on a non-empty directory."""
        try:
            info = os.stat(name, dir_fd=scratch_fd, follow_symlinks=False)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
                return False
            os.rmdir(name, dir_fd=scratch_fd)
        except OSError:
            return False
        return True

    @staticmethod
    def private_directory(scratch_fd, prefix):
        """Create a collision-safe private child relative to the checked parent, returning its name and held fd."""
        for _attempt in range(PRIVATE_DIRECTORY_ATTEMPTS):
            name = prefix + os.urandom(PRIVATE_DIRECTORY_RANDOM_BYTES).hex()
            try:
                os.mkdir(name, PRIVATE_DIRECTORY_MODE, dir_fd=scratch_fd)
            except FileExistsError:
                continue
            try:
                try:
                    fd = open_scratch(name, dir_fd=scratch_fd)
                except ValueError as e:
                    raise ConfigError(str(e)) from e
                if fd is None:
                    raise ConfigError(f"{name}: private directory disappeared")
                try:
                    if stat.S_IMODE(os.fstat(fd).st_mode) != PRIVATE_DIRECTORY_MODE:
                        raise ConfigError(f"{name}: private directory mode changed")
                except BaseException:
                    os.close(fd)
                    raise
            except BaseException:
                Run.remove_empty_private(scratch_fd, name)
                raise
            return name, fd
        raise ConfigError("cannot allocate a unique private scratch directory")

    def check_scratch_paths(self, roots, private):
        """Check current path identities against the descriptors used for creation and subsequent cleanup."""
        for path in roots:
            fd = self.guarded_scratch(path)
            os.close(fd)
        for name, fd in private:
            try:
                seen = os.stat(self.tmpdir / name, follow_symlinks=False)
            except OSError as e:
                raise ConfigError(f"{name}: private directory disappeared or became inaccessible") from e
            owned = os.fstat(fd)
            if (seen.st_dev, seen.st_ino) != (owned.st_dev, owned.st_ino):
                raise ConfigError(f"{name}: private directory was replaced")

    def low_priority(self, timeout_secs, script):
        """argv running a repo gate script at low priority, under the optional slot flock (--slot-lock)."""
        argv = ["flock", self.slot_lock] if self.slot_lock else []
        argv += ["nice", "-n", "15"]
        if shutil.which("ionice"):  # Linux only; the macOS node has no ionice
            argv += ["ionice", "-c3"]
        return [*argv, "timeout", timeout_secs, "bash", script]

    def priority_desc(self):
        """What low_priority really applies, for the cert-alone.out header (#7425)."""
        return "nice 15" + (" ionice -c3" if shutil.which("ionice") else "")

    def last_result(self, path):
        hits = RESULT_RE.findall(Path(path).read_bytes().decode("utf-8", "replace"))
        return hits[-1] if hits else None

    def check_test(self, tag, name, rc, path, expected):
        res = self.last_result(path)
        txt = f"ok/{res[1]} passed/{res[2]} failed" if res else "NO test result line"
        self.note(f"{tag}_EXIT {rc} {name} :: {txt}")
        if rc != 0 or res is None or res[0] != "ok" or res[2] != "0":
            self.fail(f"  RED {name}")
        elif res[1] == "0":
            self.fail(f"  VACUOUS {name} (0 passed)")
        elif int(res[1]) != expected:
            self.note(f"  COUNT_DIFF {name} {expected} -> {res[1]} (explain in the RUN-RECORD)")

    # ---- legs -------------------------------------------------------------------------------------------
    def battery(self):
        if not self.assert_tree(self.tip, "BATTERY"):
            return self.bad
        st = os.stat(self.wt).st_mode & 0o777
        self.note(f"== CERT LEGS {self.now()} HEAD={self.tip} host={' '.join(os.uname()[0:3:2])} umask 022 wt={st:o}")
        td_def, td_sql = self.targets / "cert7-default", self.targets / "cert7-sqlc"
        for tag, td, extra, out in (
            ("BUILD_DEFAULT", td_def, [], "build-default.log"),
            ("BUILD_SQLCIPHER", td_sql, ["--no-default-features", "--features", "sqlcipher,sal"], "build-sqlcipher.log"),
        ):
            self.note(f"== {tag} {self.now()}")
            rc = self.run([*self.cargo, "build", "-j", "6", "--release", *extra], self.outd / out,
                          {"CARGO_TARGET_DIR": str(td)}, cwd=self.wt)
            self.note(f"{tag}_EXIT {rc} {self.now()}")
            if rc != 0:
                self.fail(f"  RED {tag}")
                return self.bad
        dbin, sbin = td_def / "release/ai-memory", td_sql / "release/ai-memory"
        ver = lambda b: subprocess.run([str(b), "--version"], cwd=str(self.targets), capture_output=True, text=True,
                                         env=self.env).stdout.strip()
        sha = lambda b: subprocess.run(["sha256sum", str(b)], cwd=str(self.targets), capture_output=True,
                                       text=True).stdout[:16]
        self.note(f"bins: {ver(dbin)} / {ver(sbin)} sha256 {sha(dbin)} {sha(sbin)}")
        self.posture(dbin, sbin)
        for name, exp in BINS.items():
            out = self.outd / f"test-{name}.log"
            rc = self.run([*self.cargo, "test", "-j", "6", "--test", name], out, {"CARGO_TARGET_DIR": str(td_def)}, cwd=self.wt)
            self.check_test("TEST", name, rc, out, exp)
        for name, exp in LIBS.items():
            out = self.outd / f"lib-{name.replace(':', '_')}.log"
            rc = self.run([*self.cargo, "test", "-j", "6", "--lib", name], out, {"CARGO_TARGET_DIR": str(td_def)}, cwd=self.wt)
            self.check_test("LIB", name, rc, out, exp)
        self.note(f"BATTERY_DONE aggregate_failures={self.bad} {self.now()}")
        return self.bad

    def posture(self, dbin, sbin):
        try:
            rel, src, blob = recapture_blob(self.wt, self.tip)
        except (OSError, ValueError, subprocess.CalledProcessError) as e:
            self.fail(f"  RED posture recapture script: {e}")
            return
        self.note(f"posture script {rel} blob={blob} (tip blob)")
        ev, fix = self.outd / "evidence", self.outd / "fix"
        if rel.endswith(".py"):
            # Python form (#7378): ROOT derives from __file__; retarget the two assignments, nothing else.
            body, n_out = re.subn(r"^OUT = ROOT / .*$", lambda _m: f"OUT = Path({str(ev)!r})", src, flags=re.M)
            body, n_fix = re.subn(r"^FIX = ROOT / .*$", lambda _m: f"FIX = Path({str(fix)!r})", body, flags=re.M)
            ok = (n_out, n_fix) == (1, 1)
            # #7617: isolated, from stdin; __file__ is the checkout path, so ROOT is the checkout. No copy is written.
            argv, stdin = [sys.executable, "-I", "-c", PY_LOADER, str(self.wt / rel)], body.encode("utf-8")
        else:
            body, n_out, n_fix = retarget_shell(src, ev, fix)
            ok = (n_out, n_fix) == (1, 1) and 'FIX="$FIX"' in body
            # `bash -c BODY <checkout path>`: $0 is the checkout path, so ROOT is the checkout. No copy is written.
            argv, stdin = ["bash", "-c", body, str(self.wt / rel)], None
            if len(body.encode("utf-8")) > MAX_INLINE_SCRIPT:
                self.fail(f"  RED posture recapture script: {rel} is larger than {MAX_INLINE_SCRIPT} bytes")
                return
        if not ok:
            self.fail(f"  posture copy retarget failed OUT={n_out} FIX={n_fix}")
            return
        rc = self.run(argv, self.outd / "posture.log",
                      {"DEFAULT_BIN": str(dbin), "SQLCIPHER_BIN": str(sbin), "FIX": str(fix)}, stdin_data=stdin)
        self.note(f"POSTURE_EXIT {rc}")
        if rc != 0:
            self.fail("  RED posture recapture")
        for f in sorted(ev.glob("posture-*.out")):
            t = f.read_text(errors="replace")
            self.note(f"  {f.name} PASS={t.count('[PASS]')} FAIL={t.count('[FAIL]')}")
        codes = ev / "posture-legs-exit-codes.txt"
        if codes.exists():
            for l in codes.read_text().splitlines():
                self.note(f"  {l}")
        else:
            self.fail("  posture-legs-exit-codes.txt MISSING")
        self.note(f"POSTURE_DONE {self.now()}")

    def pg(self):
        if not self.assert_tree(self.tip, "PG"):
            return self.bad
        self.note(f"== pg coverage leg {self.now()}")
        env = {"CARGO_TARGET_DIR": str(self.targets / "cert7-pg")}
        out = self.outd / f"test-pg-{PG_BIN[0]}.log"
        rc = self.run([*self.cargo, "test", "-j", "6", "--features", "sal-postgres", "--test", PG_BIN[0]], out, env, cwd=self.wt)
        self.check_test("PGTEST", f"{PG_BIN[0]} [sal-postgres]", rc, out, PG_BIN[1])
        out = self.outd / f"lib-pg-{PG_LIB[0]}.log"
        rc = self.run([*self.cargo, "test", "-j", "6", "--features", "sal-postgres", "--lib", PG_LIB[0]], out, env, cwd=self.wt)
        self.check_test("PGLIB", f"{PG_LIB[0]} [sal-postgres]", rc, out, PG_LIB[1])
        self.note(f"PG_DONE aggregate_failures={self.bad} {self.now()}")
        return self.bad

    def removal(self):
        if not self.assert_tree(self.tip, "RP"):
            return self.bad
        started = self.now("%Y-%m-%dT%H:%M:%SZ")
        self.note(f"== removal proof {self.now()} cargo={shutil.which('cargo')}")
        full = self.outd / "removal-proof-full.log"
        env = {"CARGO_TARGET_DIR": str(self.targets / "cert7-sal"), "CARGO_BUILD_JOBS": "2",
               "AI_MEMORY_BIN": str(self.targets / "cert7-default/release/ai-memory")}
        rc = self.run(self.low_priority("14400", "scripts/check-cert-removal-proof.sh"), full, env, cwd=self.wt)
        text = full.read_bytes().decode("utf-8", "replace")
        overall = [l for l in text.splitlines() if "overall:" in l]
        proven, red = text.count("[PROVEN]"), text.count("CERT-RED]")
        hdr = [l for l in text.splitlines() if l.startswith("CERT-PROOF: tip=")]
        self.note(f"REMOVAL_PROOF_EXIT {rc} :: {overall[-1] if overall else 'NO overall line'} :: PROVEN={proven} CERT-RED={red} {self.now()}")
        self.note(f"  header: {hdr[0] if hdr else 'MISSING (#4503 header expected)'}")
        if rc != 0 or red != 0 or proven != 15:
            self.fail("  RED removal proof")
        if not hdr or f"tip={self.tip}" not in hdr[0]:
            self.fail("  removal-proof header does not name the tip")
        with (self.outd / "cert-alone.out").open("w") as f:
            f.write(f"# f2h (ai:rehearsal-f2h) standalone removal proof; worktree {self.wt}; host {os.uname().sysname} "
                    f"{os.uname().release}; flock {self.slot_lock or 'none'}; {self.priority_desc()} CARGO_BUILD_JOBS=2\n")
            f.write(f"SHA={self.git('rev-parse', 'HEAD')}\nSTARTED={started}\n{text}")
            f.write(f"PROVEN={proven}/15\nCERT_EXIT={rc}\n")
        self.run(["bash", "scripts/check-cert-removal-proof.sh", "--force-restore"], self.outd / "force-restore.log",
                 cwd=self.wt, gate=False)  # a restore must never be skipped by the floor
        d = self.dirty_tracked()
        if d:
            self.fail(f"RESTORE FAILED {len(d)} files: {d}")
        else:
            self.note("restore: clean")
        self.note(f"RP_DONE aggregate_failures={self.bad}")
        return self.bad

    def bootstrap(self):
        if not self.assert_tree(self.tip, "BCG"):
            return self.bad
        self.note(f"== bootstrap-cert-gate (self-build) {self.now()}")
        out = self.outd / "bootstrap-cert-gate.log"
        rc = self.run(self.low_priority("7200", "scripts/check-bootstrap-cert-gate.sh"), out, {"CARGO_BUILD_JOBS": "2"},
                      cwd=self.wt)
        lines = [l for l in out.read_bytes().decode("utf-8", "replace").splitlines() if l.strip()]
        self.note(f"BOOTSTRAP_CERT_GATE_EXIT {rc} :: {lines[-1][:200] if lines else 'EMPTY'}")
        if rc != 0:
            self.fail("  RED bootstrap cert gate")
        d = self.dirty_tracked()
        if d:
            self.fail(f"BCG left {len(d)} tracked files dirty")
        self.note(f"BCG_DONE aggregate_failures={self.bad} {self.now()}")
        return self.bad

    def chain(self):
        if self.battery() != 0:
            self.note("CHAIN: battery not green; removal proof NOT started")
            return self.bad
        for leg in (self.removal, self.pg, self.bootstrap):
            before = self.bad
            leg()
            self.note(f"CHAIN: {leg.__name__} new_failures={self.bad - before}")
        self.note(f"CHAIN_DONE aggregate_failures={self.bad} {self.now()}")
        return self.bad

    # ---- cert-commit gates --------------------------------------------------------------------------------
    def gates(self, prior_bind, push_branch, parent="", also_evidence=()):
        return self._gates(prior_bind, push_branch, parent, also_evidence)

    def _gates(self, prior_bind, push_branch, parent, also_evidence):
        head = self.git("rev-parse", "HEAD")
        if self.dirty_tracked():
            self.fail("GATES DIRTY")
            return self.bad
        parent = parent or self.tip
        if self.git("rev-parse", "HEAD^") != parent:
            self.fail(f"GATES: HEAD^ is not {parent} (the gated commit must be the ONE commit on it)")
        short = self.tip[:9]
        dirs = tuple(f"docs/compliance/evidence/cert-{s}/" for s in (short, *also_evidence))
        touched = self.git("diff", "--name-only", "--no-renames", f"{parent}..HEAD").splitlines()
        stray = [p for p in touched if not (p == CERT_DOC or p.startswith(dirs))]
        self.note(f"SCOPE allowed={[CERT_DOC, *dirs]}")
        self.note(f"SCOPE touched={len(touched)} stray={stray}")
        if stray or CERT_DOC not in touched:
            self.fail("  RED scope: the cert commit may touch only the cert doc and its own evidence dir")
        gl = self.outd / "g"
        try:
            sfd = self.open_scratch()
        except ValueError as e:
            self.fail(f"  RED scratch {e}")
            return self.bad
        if sfd is not None:
            try:
                self.sweep_legacy(sfd)
            finally:
                os.close(sfd)
        # The expiry gate is the Python port (#6137), taken from the gated commit's blob, never the disk (#7439), and
        # run from memory: no copy of it is ever written (#7618).
        try:
            expiry, gate_blob, gate_sha = self.expiry_gate()
        except (OSError, ValueError, subprocess.CalledProcessError) as e:
            self.fail(f"  RED expiry gate: {e}")
            return self.bad
        self.note(f"{EXPIRY_PY} blob={gate_sha} (HEAD tree; run from memory, nothing is written)")
        checks = [
            ("cert-expiry-upstream", expiry, {}),
            (f"cert-expiry-{prior_bind[:9]}", expiry, {"CERT_EXPIRY_BASE": prior_bind}),
            ("cert-expiry-selftest", [*expiry, "--self-test"], {}),
            ("removal-proof-header-selftest", ["bash", self.script("check-cert-removal-proof.sh"), "--self-test-header"], {}),
            ("docs-vs-ssot", ["bash", self.script("check-docs-vs-ssot.sh")], {}),
            ("doc-anchors", ["bash", self.script("check-doc-symbol-anchors.sh")], {}),
            ("ci-job-claims", ["bash", self.script("check-ci-job-claims.sh")], {}),
            ("hardcoded", ["bash", self.script("check-hardcoded-literals.sh")], {}),
            ("vendor", ["bash", self.script("check-vendor-literals.sh")], {}),
            ("c8", ["bash", self.script("qc-codegraph-precheck.sh")], {}),
            ("envlock", ["bash", self.script("check-test-env-lock.sh")], {}),
            ("count", ["bash", self.script("check-count-assertion-declared.sh"), "--range", f"{parent}..HEAD"], {}),
            ("ftc", ["bash", self.script("check-foreign-text-to-caller.sh")], {}),
        ]
        for name, argv, extra in checks:
            out = Path(f"{gl}.{name}.log")
            # no cargo here, so the disk floor does not apply; the child's cwd is a fresh sandbox (#7661, #7665)
            rc = self.run(argv, out, extra, gate=False,
                          stdin_data=gate_blob if name.startswith("cert-expiry") else None)
            lines = [l for l in out.read_text(errors="replace").splitlines() if l.strip()]
            self.note(f"{rc} {name} :: {lines[-1][:160] if lines else 'EMPTY'}")
            if rc != 0:
                self.fail(f"  RED {name}")
        sig = self.git("log", "-1", "--format=%G?")
        self.note(f"signature %G?={sig}")
        if sig != "G":
            self.fail("  RED signature")
        self.note(f"GATES head={head} fails={self.bad}")
        if self.bad == 0 and push_branch:
            self.push_gated(head, push_branch)
        return self.bad

    def expiry_gate(self):
        """(argv, blob bytes, blob sha) of the cert-expiry gate: HEAD's blob of scripts/check_cert_expiry.py, run as
        `python -I -c PY_LOADER <checkout path>` with the blob on stdin (#7439, #7581, #7618). Nothing is written, so
        there is no copy to replace between a check and the exec. The loader sets __file__ to the checkout path, so the
        gate's REPO_ROOT (the parent of its scripts directory) is the checkout and its own scratch is the checkout's
        .local-runs. Isolated mode keeps the working directory and the environment's PYTHON* variables off sys.path.
        No shell fallback; a missing or non-regular (symlink) entry raises."""
        sha, data = blob_bytes(self.wt, "HEAD", EXPIRY_PY)
        return [sys.executable, "-I", "-c", PY_LOADER, str(self.wt / EXPIRY_PY)], data, sha

    def open_scratch(self):
        """The checkout's .local-runs through the shared guard (#7662, #7668)."""
        return open_scratch(self.wt / ".local-runs")

    def script(self, name):
        """The absolute path of a repository gate script, so it runs from the sandbox cwd (the script cds to its root)."""
        return str(self.wt / "scripts" / name)

    @staticmethod
    def remove_tree(dfd, name, *, expected_identity=None):
        """Remove the entry `name` of the directory fd `dfd` without recursion and without following a symlink: files and
        symlinks are unlinked themselves, directories are descended into by O_DIRECTORY|O_NOFOLLOW open relative to the
        current fd, and left again through ".." with the parent's device and inode checked. One directory fd is held at a
        time, so depth costs no stack and no descriptors. ValueError when the tree is deeper than SWEEP_MAX_DEPTH or an
        entry was swapped under the walk (#7582, #7620)."""
        flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
        top = os.stat(name, dir_fd=dfd, follow_symlinks=False)
        if expected_identity is not None and (top.st_dev, top.st_ino) != expected_identity:
            raise ValueError(f"{name} was replaced; left in place")
        if not stat.S_ISDIR(top.st_mode):
            os.unlink(name, dir_fd=dfd)
            return
        chain = [(name, (top.st_dev, top.st_ino))]
        cur = os.open(name, flags, dir_fd=dfd)
        try:
            if (os.fstat(cur).st_dev, os.fstat(cur).st_ino) != chain[0][1]:
                raise ValueError(f"{name} was replaced while it was opened")
            while True:
                child = None
                for entry in list(os.scandir(cur)):
                    if entry.is_dir(follow_symlinks=False):
                        child = entry.name
                        break
                    os.unlink(entry.name, dir_fd=cur)
                if child is not None:
                    if len(chain) >= SWEEP_MAX_DEPTH:
                        raise ValueError(f"{name} is nested deeper than {SWEEP_MAX_DEPTH} levels; left in place")
                    seen = os.stat(child, dir_fd=cur, follow_symlinks=False)
                    nxt = os.open(child, flags, dir_fd=cur)
                    now = os.fstat(nxt)
                    if (now.st_dev, now.st_ino) != (seen.st_dev, seen.st_ino):
                        os.close(nxt)
                        raise ValueError(f"{child} was replaced while it was opened")
                    chain.append((child, (now.st_dev, now.st_ino)))
                    os.close(cur)
                    cur = nxt
                    continue
                if len(chain) == 1:
                    break
                gone, _ident = chain.pop()
                up = os.open("..", flags, dir_fd=cur)
                os.close(cur)
                cur = up
                here = os.fstat(cur)
                if (here.st_dev, here.st_ino) != chain[-1][1]:
                    raise ValueError(f"the parent of {gone} is not the directory the walk came from")
                os.rmdir(gone, dir_fd=cur)
        finally:
            os.close(cur)
        if expected_identity is not None:
            now = os.stat(name, dir_fd=dfd, follow_symlinks=False)
            if (now.st_dev, now.st_ino) != expected_identity:
                raise ValueError(f"{name} was replaced; left in place")
        os.rmdir(name, dir_fd=dfd)

    def sweep_legacy(self, dfd):
        """Remove the .expiry-* entries that earlier runs left in the scratch directory `dfd`: the ones whose pid is gone,
        and any of the older layout. The gate no longer writes such entries (#7618); this only cleans up. An entry whose
        pid is alive is left alone. Each failure is a NOTE row, never an exception: a leftover must not end the run
        (#7620)."""
        try:
            names = sorted(e.name for e in os.scandir(dfd) if e.name.startswith(".expiry-"))
        except OSError as e:
            self.note(f"NOTE sweep cannot list the scratch directory: {e}")
            return
        for name in names:
            m = re.match(r"\.expiry-(\d+)-", name)
            if m:
                alive = True
                try:
                    os.kill(int(m.group(1)), 0)
                except ProcessLookupError:
                    alive = False
                except PermissionError:
                    alive = True  # the process exists under another user
                if alive:
                    continue
            try:
                self.remove_tree(dfd, name)
            except Exception as e:  # noqa: BLE001 - any failure of a cleanup is reported, never raised
                self.note(f"NOTE sweep {name}: {type(e).__name__}: {e}")

    def push_gated(self, head, branch):
        """Push the gated commit; a failed push, or a remote ref that is not the gated head, is a failure (#7422)."""
        r = subprocess.run(["git", "push", "-q", "origin", f"HEAD:refs/heads/{branch}"], cwd=self.wt,
                           capture_output=True, text=True, env=self.env)
        self.note(f"PUSH rc={r.returncode} {r.stderr.strip()[:200]}")
        remote = self.git("ls-remote", "origin", f"refs/heads/{branch}")
        self.note(remote)
        if r.returncode != 0:
            self.fail("  RED push: git push failed")
        elif not remote.startswith(head):
            self.fail("  RED push: the remote ref is not the gated head")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("leg", choices=["battery", "pg", "removal", "bootstrap", "chain", "gates"])
    ap.add_argument("--tip", required=True, help="full 40-hex CERT TIP FINAL sha")
    ap.add_argument("--wt", required=True)
    ap.add_argument("--outd", required=True)
    ap.add_argument("--cargo-slot", default="", help="cargo semaphore wrapper, run as `<wrapper> cargo ...` "
                    "(default: $CERT_CARGO_SLOT, else plain cargo)")
    ap.add_argument("--slot-lock", default="", help="flock file serialising the removal-proof and bootstrap legs "
                    "(default: $CERT_SLOT_LOCK, else no flock)")
    ap.add_argument("--targets", default="", help=f"cargo target dirs (default: $CERT_TARGETS, else {DEFAULT_TARGETS})")
    ap.add_argument("--tmpdir", default="", help=f"TMPDIR for every leg (default: $CERT_TMPDIR, else {DEFAULT_TMPDIR})")
    ap.add_argument("--prior-bind", default="385da3a054c4f82bcdfd51ec2d8f07ca4947f9a5")
    ap.add_argument("--push-branch", default="", help="gates only: branch to push when fails == 0")
    ap.add_argument("--parent", default="", help="gates only: expected HEAD^ for a follow-up on the cert commit (default: --tip)")
    ap.add_argument("--also-evidence", action="append", default=[], metavar="SHORT9",
                    help="gates only: an earlier cert's 9-hex evidence-dir id the commit may also touch (repeatable)")
    a = ap.parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}", a.tip):
        print("--tip must be a full 40-hex sha", file=sys.stderr)
        return 64
    bad_ids = [s for s in a.also_evidence if not re.fullmatch(r"[0-9a-f]{9}", s)]
    if bad_ids or (a.also_evidence and a.leg != "gates"):
        print(f"--also-evidence must be 9-hex ids and is a gates-only option: {a.also_evidence}", file=sys.stderr)
        return 64
    given = [opt for opt, val in (("--push-branch", a.push_branch), ("--parent", a.parent)) if val]
    if given and a.leg != "gates":
        print(f"{' and '.join(given)} {'is a' if len(given) == 1 else 'are'} gates-only option"
              f"{'' if len(given) == 1 else 's'}; the {a.leg} leg would ignore it. Run the gates leg, or drop the option.",
              file=sys.stderr)
        return 64
    try:
        r = Run(a)
    except ConfigError as e:
        print(f"run_cert: {e}", file=sys.stderr)
        return 64
    r.note(r.config_row())
    r.note(r.plan_row(a.leg))
    try:
        r.preflight()
    except ConfigError as e:
        print(f"run_cert: {e}", file=sys.stderr)
        r.fail(f"  RED preflight: {e}")
        r.note(f"EXIT=64 leg={a.leg} aggregate_failures={r.bad} {r.now()}")
        return 64
    try:
        if a.leg == "gates":
            rc = r.gates(a.prior_bind, a.push_branch, a.parent, tuple(a.also_evidence))
        else:
            rc = getattr(r, a.leg)()
    except Exception as e:  # noqa: BLE001 - a leg never ends the run without its EXIT row (#7620)
        r.fail(f"  RED internal {type(e).__name__}: {e}")
        rc = r.bad or 1
    r.note(f"EXIT={1 if rc else 0} leg={a.leg} aggregate_failures={rc} {r.now()}")
    return 1 if rc else 0


if __name__ == "__main__":
    sys.exit(main())
