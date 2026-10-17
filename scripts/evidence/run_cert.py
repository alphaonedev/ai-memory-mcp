#!/usr/bin/env python3
"""§7 enterprise-federation cert re-issue runner (ai:rehearsal-f2h). Python port of the certv2 shell harness.

Subcommands (every one asserts the worktree HEAD == --tip and a clean tracked tree first):
  battery    release builds (default; --no-default-features sqlcipher,sal), posture recapture (4 legs),
             8 named integration bins + 3 lib slices (default features), each via cargo-slot.py
  pg         #4434 coverage leg under --features sal-postgres (1 bin + 1 lib slice), via cargo-slot.py
  removal    scripts/check-cert-removal-proof.sh BARE under flock slot-3, nice 15, ionice -c3, CARGO_BUILD_JOBS=2;
             writes cert-alone.out; then --force-restore and a dirty check
  bootstrap  scripts/check-bootstrap-cert-gate.sh self-build path under the same flock slot
  chain      battery; if green: removal, pg, bootstrap (each runs whatever the previous one returned)
  gates      on the CERT COMMIT (HEAD = one commit on top of --tip): the cargo-free gates, the scope gate
             (only the cert doc + its evidence dir), %G? = G; pushes --push-branch only when fails == 0

Every outcome is a line in OUTD/legs.log (the gates leg: OUTD/gates.log, #5042); exit status is the aggregate
(0 = every leg green). Paths default to the checkout (.local-runs/); see the --cargo-slot/--slot-lock/--targets/--tmpdir options.
"""
import argparse
import datetime
import os
import re
import shutil
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


def pick_recapture(wt):
    """The posture recapture script of the gated worktree: the Python port first, the shell script second (#7399)."""
    for rel in RECAPTURE_CANDIDATES:
        if (Path(wt) / rel).is_file():
            return Path(wt) / rel
    raise FileNotFoundError("no recapture script in the gated worktree; looked for "
                            + " then ".join(RECAPTURE_CANDIDATES))


class Run:
    def __init__(self, a):
        self.tip = a.tip
        self.wt = Path(a.wt)
        self.outd = Path(a.outd)
        self.outd.mkdir(parents=True, exist_ok=True)
        # #5042: the gates leg runs after the chain and writes its own artifact, so the RUN-RECORD legs-log hash and
        # the bundle builder's chain gate read the chain's rows alone.
        self.log = self.outd / ("gates.log" if a.leg == "gates" else "legs.log")
        self.targets = Path(getattr(a, "targets", None) or os.environ.get("CERT_TARGETS") or DEFAULT_TARGETS)
        self.tmpdir = Path(getattr(a, "tmpdir", None) or os.environ.get("CERT_TMPDIR") or DEFAULT_TMPDIR)
        slot = getattr(a, "cargo_slot", None) or os.environ.get("CERT_CARGO_SLOT") or ""
        self.cargo = [slot, "cargo"] if slot else ["cargo"]
        self.slot_lock = getattr(a, "slot_lock", None) or os.environ.get("CERT_SLOT_LOCK") or ""
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
        with open(out, "wb") as f:
            return subprocess.run(argv, cwd=cwd or self.wt, env=env, stdout=f, stderr=subprocess.STDOUT,
                                  stdin=subprocess.DEVNULL).returncode

    def low_priority(self, timeout_secs, script):
        """argv running a repo gate script at low priority, under the optional slot flock (--slot-lock)."""
        argv = ["flock", self.slot_lock] if self.slot_lock else []
        argv += ["nice", "-n", "15"]
        if shutil.which("ionice"):  # Linux only; the macOS node has no ionice
            argv += ["ionice", "-c3"]
        return [*argv, "timeout", timeout_secs, "bash", script]

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
            script = pick_recapture(self.wt)
        except FileNotFoundError as e:
            self.fail(f"  RED posture recapture script: {e}")
            return
        src = script.read_text()
        ev, fix = self.outd / "evidence", self.outd / "fix"
        if script.suffix == ".py":
            # Python form (#7378): ROOT derives from __file__; retarget the two assignments, nothing else.
            body, n_out = re.subn(r"^OUT = ROOT / .*$", lambda _m: f"OUT = Path({str(ev)!r})", src, flags=re.M)
            body, n_fix = re.subn(r"^FIX = ROOT / .*$", lambda _m: f"FIX = Path({str(fix)!r})", body, flags=re.M)
            ok = (n_out, n_fix) == (1, 1)
            tmp, argv = self.wt / "scripts/.recapture-cert7.py", [sys.executable]
        else:
            # Retarget only the two $ROOT-relative assignments; the column-0 FIX="$FIX" line must stay untouched.
            body, n_out = re.subn(r'^OUT="\$ROOT/[^"\n]*"$', f'OUT="{ev}"', src, flags=re.M)
            body, n_fix = re.subn(r'^FIX="\$ROOT/[^"\n]*"$', f'FIX="{fix}"', body, flags=re.M)
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
                    f"{os.uname().release}; flock {self.slot_lock or 'none'}; nice 15 ionice -c3 CARGO_BUILD_JOBS=2\n")
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
        # The expiry gate was ported from check-cert-expiry.sh to check_cert_expiry.py (#6137); a gated worktree
        # older than the port still has the shell script.
        expiry = ([sys.executable, "scripts/check_cert_expiry.py"] if (self.wt / "scripts/check_cert_expiry.py").is_file()
                  else ["bash", "scripts/check-cert-expiry.sh"])
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
            r = subprocess.run(["git", "push", "-q", "origin", f"HEAD:refs/heads/{push_branch}"], cwd=self.wt,
                               capture_output=True, text=True, env=self.env)
            self.note(f"PUSH rc={r.returncode} {r.stderr.strip()[:200]}")
            self.note(self.git("ls-remote", "origin", f"refs/heads/{push_branch}"))
        return self.bad


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
    r = Run(a)
    if a.leg == "gates":
        bad_ids = [s for s in a.also_evidence if not re.fullmatch(r"[0-9a-f]{9}", s)]
        if bad_ids:
            print(f"--also-evidence must be 9-hex ids: {bad_ids}", file=sys.stderr)
            return 64
        rc = r.gates(a.prior_bind, a.push_branch, a.parent, tuple(a.also_evidence))
    else:
        rc = getattr(r, a.leg)()
    r.note(f"EXIT={1 if rc else 0} leg={a.leg} aggregate_failures={rc} {r.now()}")
    return 1 if rc else 0


if __name__ == "__main__":
    sys.exit(main())
