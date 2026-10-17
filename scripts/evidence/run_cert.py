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
import argparse
import contextlib
import datetime
import os
import re
import shlex
import secrets
import shutil
import stat
import subprocess
import sys
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
    return subprocess.run(["git", "-C", str(wt), "cat-file", "-e", f"{rev}:{rel}"], capture_output=True).returncode == 0


def tree_entry(wt, rev, rel):
    """(mode, type, sha) of rel in rev's tree, or None when it is not tracked there."""
    r = subprocess.run(["git", "-C", str(wt), "ls-tree", rev, "--", rel], capture_output=True, text=True)
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
    return sha, subprocess.run(["git", "-C", str(wt), "cat-file", "blob", sha], capture_output=True, check=True).stdout


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
        self.expiry_copy = self.expiry_dfd = self.expiry_name = self.expiry_data = None
        self.expiry_ident = self.expiry_dir_ident = None
        self.outd.mkdir(parents=True, exist_ok=True)
        self.targets.mkdir(parents=True, exist_ok=True)
        self.tmpdir.mkdir(parents=True, exist_ok=True)
        self.bad = 0
        self.floor_tripped = False
        os.umask(0o022)
        self.env = dict(os.environ)
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
        """GOD 7caf919e: df before every cargo leg, stop below the floor. Once tripped, nothing else runs."""
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

    def run(self, argv, out, extra_env=None, cwd=None, gate=True):
        if gate and not self.floor_ok(" ".join(map(str, argv))[:120]):
            Path(out).write_text("NOT RUN: disk floor tripped\n")
            return 75
        env = dict(self.env)
        env.update(extra_env or {})
        try:
            with open(out, "wb") as f:
                return subprocess.run(argv, cwd=cwd or self.wt, env=env, stdout=f, stderr=subprocess.STDOUT,
                                      stdin=subprocess.DEVNULL).returncode
        except OSError as e:  # a missing wrapper, flock or timeout (#7420): a RED row and 127, never a traceback
            print(f"run_cert: cannot start {argv[0]!r}: {e.strerror or e}. Check that --cargo-slot / CERT_CARGO_SLOT "
                  "names an executable wrapper and that flock, nice and timeout are installed.", file=sys.stderr)
            Path(out).write_text(f"NOT RUN: cannot start {argv[0]}: {e}\n")
            self.fail(f"  RED launch {argv[0]}: {e.strerror or e}")
            return 127

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
                          {"CARGO_TARGET_DIR": str(td)})
            self.note(f"{tag}_EXIT {rc} {self.now()}")
            if rc != 0:
                self.fail(f"  RED {tag}")
                return self.bad
        dbin, sbin = td_def / "release/ai-memory", td_sql / "release/ai-memory"
        ver = lambda b: subprocess.run([str(b), "--version"], capture_output=True, text=True, env=self.env).stdout.strip()
        sha = lambda b: subprocess.run(["sha256sum", str(b)], capture_output=True, text=True).stdout[:16]
        self.note(f"bins: {ver(dbin)} / {ver(sbin)} sha256 {sha(dbin)} {sha(sbin)}")
        self.posture(dbin, sbin)
        for name, exp in BINS.items():
            out = self.outd / f"test-{name}.log"
            rc = self.run([*self.cargo, "test", "-j", "6", "--test", name], out, {"CARGO_TARGET_DIR": str(td_def)})
            self.check_test("TEST", name, rc, out, exp)
        for name, exp in LIBS.items():
            out = self.outd / f"lib-{name.replace(':', '_')}.log"
            rc = self.run([*self.cargo, "test", "-j", "6", "--lib", name], out, {"CARGO_TARGET_DIR": str(td_def)})
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
            tmp, argv = self.wt / "scripts/.recapture-cert7.py", [sys.executable]
        else:
            body, n_out, n_fix = retarget_shell(src, ev, fix)
            ok = (n_out, n_fix) == (1, 1) and 'FIX="$FIX"' in body
            tmp, argv = self.wt / "scripts/.recapture-cert7.sh", ["bash"]
        if not ok:
            self.fail(f"  posture copy retarget failed OUT={n_out} FIX={n_fix}")
            return
        tmp.write_text(body)
        try:
            rc = self.run([*argv, str(tmp)], self.outd / "posture.log",
                          {"DEFAULT_BIN": str(dbin), "SQLCIPHER_BIN": str(sbin), "FIX": str(fix)})
        finally:
            tmp.unlink()
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
        rc = self.run([*self.cargo, "test", "-j", "6", "--features", "sal-postgres", "--test", PG_BIN[0]], out, env)
        self.check_test("PGTEST", f"{PG_BIN[0]} [sal-postgres]", rc, out, PG_BIN[1])
        out = self.outd / f"lib-pg-{PG_LIB[0]}.log"
        rc = self.run([*self.cargo, "test", "-j", "6", "--features", "sal-postgres", "--lib", PG_LIB[0]], out, env)
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
        rc = self.run(self.low_priority("14400", "scripts/check-cert-removal-proof.sh"), full, env)
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
                 gate=False)  # a restore must never be skipped by the floor
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
        rc = self.run(self.low_priority("7200", "scripts/check-bootstrap-cert-gate.sh"), out, {"CARGO_BUILD_JOBS": "2"})
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
        try:
            return self._gates(prior_bind, push_branch, parent, also_evidence)
        finally:
            self.drop_expiry()

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
        # The expiry gate is the Python port (#6137), taken from the gated commit's blob, never the disk (#7439).
        try:
            expiry = self.pick_expiry()
        except (OSError, ValueError, subprocess.CalledProcessError) as e:
            self.fail(f"  RED expiry gate: {e}")
            return self.bad
        checks = [
            ("cert-expiry-upstream", expiry, {}),
            (f"cert-expiry-{prior_bind[:9]}", expiry, {"CERT_EXPIRY_BASE": prior_bind}),
            ("cert-expiry-selftest", [*expiry, "--self-test"], {}),
            ("removal-proof-header-selftest", ["bash", "scripts/check-cert-removal-proof.sh", "--self-test-header"], {}),
            ("docs-vs-ssot", ["bash", "scripts/check-docs-vs-ssot.sh"], {}),
            ("doc-anchors", ["bash", "scripts/check-doc-symbol-anchors.sh"], {}),
            ("ci-job-claims", ["bash", "scripts/check-ci-job-claims.sh"], {}),
            ("hardcoded", ["bash", "scripts/check-hardcoded-literals.sh"], {}),
            ("vendor", ["bash", "scripts/check-vendor-literals.sh"], {}),
            ("c8", ["bash", "scripts/qc-codegraph-precheck.sh"], {}),
            ("envlock", ["bash", "scripts/check-test-env-lock.sh"], {}),
            ("count", ["bash", "scripts/check-count-assertion-declared.sh", "--range", f"{parent}..HEAD"], {}),
            ("ftc", ["bash", "scripts/check-foreign-text-to-caller.sh"], {}),
        ]
        for name, argv, extra in checks:
            if name.startswith("cert-expiry"):
                try:
                    self.check_expiry_copy()  # #7581: the path must still name the copy that was made
                except ValueError as e:
                    self.fail(f"  RED expiry gate copy: {e}")
                    continue
            out = Path(f"{gl}.{name}.log")
            rc = self.run(argv, out, extra)
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

    def pick_expiry(self):
        """argv of the cert-expiry gate, run as `python -I <copy>` from a copy of HEAD's blob of scripts/check_cert_expiry.py
        (#7439, #7581). No shell fallback; a missing or non-regular (symlink) entry raises. The gate sets REPO_ROOT to
        its own path's parent.parent, so the copy is a file named .expiry-<pid>-<random>.py directly inside
        <wt>/.local-runs: its parent.parent is then the checkout, and the gate's own scratch is the one
        <wt>/.local-runs (no nested .local-runs/.local-runs, #7531). That layout is why the copy is not put in a
        private subdirectory; isolated mode (-I) keeps the copy's own directory off sys.path, so a module planted
        beside it never replaces the gate (#7581).
        What is enforced: .local-runs is opened once, O_DIRECTORY|O_NOFOLLOW; the copy is created relative to that
        directory fd with O_EXCL|O_NOFOLLOW, mode 0600; the sweep of stale copies (their pid is gone) and the removal
        of the copy go through the same directory fd and never follow a symlink (#7532, #7582). The gate is started
        from the path, so before each run check_expiry_copy() confirms that the path still names the same directory
        and the same file (device and inode) and that the bytes are the blob's; a mismatch is refused. The window
        between that check and the exec is not closed, only narrowed. drop_expiry() removes the copy."""
        sha, data = blob_bytes(self.wt, "HEAD", EXPIRY_PY)
        scratch = self.wt / ".local-runs"
        try:
            scratch.mkdir(exist_ok=True)
        except FileExistsError:
            pass  # a symlink, a dangling link or a regular file: the open below decides
        try:
            dfd = os.open(scratch, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
        except OSError as e:
            if scratch.is_symlink():
                raise ValueError(f"{scratch} is a symlink; the expiry gate copy is not written through it") from e
            raise
        name = f".expiry-{os.getpid()}-{secrets.token_hex(6)}.py"
        try:
            self.sweep_expiry(dfd)
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=dfd)
        except BaseException:
            os.close(dfd)
            raise
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
                f.flush()
                ident = os.fstat(f.fileno())
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(name, dir_fd=dfd)
            os.close(dfd)
            raise
        self.expiry_dfd, self.expiry_name, self.expiry_data = dfd, name, data
        self.expiry_ident, self.expiry_dir_ident = (ident.st_dev, ident.st_ino), os.fstat(dfd)
        self.expiry_copy = scratch / name
        try:
            self.check_expiry_copy()
        except ValueError:
            self.drop_expiry()
            raise
        self.note(f"{EXPIRY_PY} blob={sha} (HEAD tree; run from a copy of the blob)")
        return [sys.executable, "-I", str(self.expiry_copy)]

    def check_expiry_copy(self):
        """Raise ValueError unless the copy's path still names the directory fd opened by pick_expiry and the very file
        it created (same device and inode, a regular file, the blob's bytes). Called before every run of the gate."""
        if self.expiry_copy is None:
            raise ValueError("no expiry gate copy was made")
        try:
            dst = os.lstat(self.expiry_copy.parent)
            dev, ino = self.expiry_dir_ident.st_dev, self.expiry_dir_ident.st_ino
            if not stat.S_ISDIR(dst.st_mode) or (dst.st_dev, dst.st_ino) != (dev, ino):
                raise ValueError(f"{self.expiry_copy.parent} no longer names the directory the copy was made in")
            fd = os.open(self.expiry_copy, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        except OSError as e:
            raise ValueError(f"the expiry gate copy {self.expiry_copy} cannot be re-opened: {e}") from e
        with os.fdopen(fd, "rb") as f:
            st = os.fstat(f.fileno())
            if not stat.S_ISREG(st.st_mode) or (st.st_dev, st.st_ino) != self.expiry_ident:
                raise ValueError(f"the expiry gate copy {self.expiry_copy} is not the file that was created")
            if f.read() != self.expiry_data:
                raise ValueError(f"the expiry gate copy {self.expiry_copy} was modified after it was created")

    @staticmethod
    def remove_at(dfd, name):
        """Remove the entry `name` of the directory fd `dfd` without following a symlink: a directory is emptied through
        its own fd (O_DIRECTORY|O_NOFOLLOW), a symlink or file is unlinked itself (#7582)."""
        if stat.S_ISDIR(os.stat(name, dir_fd=dfd, follow_symlinks=False).st_mode):
            sub = os.open(name, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0), dir_fd=dfd)
            try:
                for entry in [e.name for e in os.scandir(sub)]:
                    Run.remove_at(sub, entry)
            finally:
                os.close(sub)
            os.rmdir(name, dir_fd=dfd)
        else:
            os.unlink(name, dir_fd=dfd)

    @staticmethod
    def sweep_expiry(dfd):
        """Remove .expiry-* entries a killed run left in the scratch directory `dfd`: those whose pid is gone, and any
        entry of the older directory layout. A live run's copy (its pid is alive) is not touched. Every call is
        relative to the directory fd, so a path swapped for a symlink cannot redirect it (#7532, #7582)."""
        for name in [e.name for e in os.scandir(dfd)]:
            if not name.startswith(".expiry-"):
                continue
            m = re.match(r"\.expiry-(\d+)-", name)
            if m:
                pid = int(m.group(1))
                try:
                    os.kill(pid, 0)
                    continue  # alive (or ours)
                except ProcessLookupError:
                    pass
                except PermissionError:
                    continue  # alive, another user
            with contextlib.suppress(OSError):  # best effort: a leftover never blocks the run
                Run.remove_at(dfd, name)

    def drop_expiry(self):
        """Remove the copy through the directory fd (never the path) and close the fd."""
        if self.expiry_dfd is not None:
            with contextlib.suppress(OSError):
                os.unlink(self.expiry_name, dir_fd=self.expiry_dfd)
            with contextlib.suppress(OSError):
                os.close(self.expiry_dfd)
        self.expiry_copy = self.expiry_dfd = self.expiry_name = self.expiry_data = None

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
    if a.leg == "gates":
        rc = r.gates(a.prior_bind, a.push_branch, a.parent, tuple(a.also_evidence))
    else:
        rc = getattr(r, a.leg)()
    r.note(f"EXIT={1 if rc else 0} leg={a.leg} aggregate_failures={rc} {r.now()}")
    return 1 if rc else 0


if __name__ == "__main__":
    sys.exit(main())
