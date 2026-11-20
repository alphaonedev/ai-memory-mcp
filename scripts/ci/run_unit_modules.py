#!/usr/bin/env python3
"""Run the scripts/ci unit test modules in parallel, one process per module, failing closed (#9734).

Class: a serial run of independent test modules on a multi-core runner. Invariant: every
`test*.py` module of the tests directory runs exactly once, any module that is not rc 0, times
out, prints no `Ran` line or runs zero tests makes the run exit 1, and the wall time is bounded
by the slowest module plus the queue, not by the sum.

Each module runs as `python -m unittest discover -s <tests dir> -p <module>` (the form the
merged-tree tool uses). One line per module: `<module> rc=<n> <Ran line> | <result> <seconds>s`,
then `SUMMARY modules=N bad=K [names] tests=T wall=Ws`, then the full output of every bad module.

Exit codes: 0 all modules green; 1 a module is bad; 2 usage or discovery error (no modules, a
missing directory, a module file that vanished, a SERIAL_MODULES name that matches no module).

Python 3.12+, standard library only.
"""
import argparse
import os
import re
import signal
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
DEFAULT_TESTS_DIR = REPO / "scripts" / "ci" / "tests"
MODULE_GLOB = "test*.py"  # the default pattern of `unittest discover`
DEFAULT_TIMEOUT_S = 1800  # a hang bound, not a speed target: the slowest module took 671 s on a host at load 44
EXIT_OK = 0
EXIT_BAD_MODULE = 1
EXIT_USAGE = 2
RAN_RE = re.compile(r"^Ran (\d+) tests? in ", re.MULTILINE)
RESULT_RE = re.compile(r"^(OK.*|FAILED.*)$", re.MULTILINE)
TAIL_CHARS = 400

# Modules that must not share the pool, each with the reason. They run one at a time after the pool.
SERIAL_MODULES: dict[str, str] = {
    "test_cert_amendment_ledger_6124.py": (
        "asserts absolute 1.0 s wall-clock bounds on 100K-line inputs; red at 2.4 s when the CPU is shared (seen at jobs=8)"
    ),
    "test_certification_scope_8262.py": (
        "asserts absolute 2.0 s wall-clock bounds on 100K-char inputs; same shared-CPU sensitivity as the ledger module"
    ),
}


class DiscoveryError(Exception):
    """A usage or discovery problem (exit 2), never a test failure."""


@dataclass
class ModuleResult:
    name: str
    rc: int | None
    ran: int
    ran_line: str
    result_line: str
    seconds: float
    timed_out: bool
    output: str

    @property
    def bad(self) -> bool:
        # No `Ran` line parses to ran == 0, so ran == 0 also fails a module that printed none.
        return self.timed_out or self.rc != 0 or self.ran == 0

    def line(self) -> str:
        if self.timed_out:
            return "%s rc=TIMEOUT %s | TIMEOUT %.1fs" % (self.name, self.ran_line or "no Ran line", self.seconds)
        return "%s rc=%s %s | %s %.1fs" % (self.name, self.rc, self.ran_line or "no Ran line",
                                           self.result_line or "no result line", self.seconds)


@dataclass
class RunResult:
    modules: list[ModuleResult] = field(default_factory=list)
    wall: float = 0.0

    @property
    def bad(self) -> list[str]:
        return [m.name for m in self.modules if m.bad]

    @property
    def tests(self) -> int:
        return sum(m.ran for m in self.modules)

    def summary(self) -> str:
        return "SUMMARY modules=%d bad=%d [%s] tests=%d wall=%.1fs" % (
            len(self.modules), len(self.bad), ",".join(self.bad), self.tests, self.wall)


def discover_modules(tests_dir: Path) -> list[str]:
    """The module file names plain `unittest discover` would load (top level `test*.py`)."""
    if not tests_dir.is_dir():
        raise DiscoveryError("tests directory %s does not exist" % tests_dir)
    return sorted(p.name for p in tests_dir.glob(MODULE_GLOB) if p.is_file())


def run_one(name: str, tests_dir: Path, repo: Path, timeout_s: float) -> ModuleResult:
    if not (tests_dir / name).is_file():
        raise DiscoveryError("module %s vanished from %s" % (name, tests_dir))
    cmd = [sys.executable, "-m", "unittest", "discover", "-s", str(tests_dir), "-p", name]
    started = time.monotonic()
    proc = subprocess.Popen(cmd, cwd=repo, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, start_new_session=True)
    timed_out = False
    try:
        out, _ = proc.communicate(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        timed_out = True
        os.killpg(proc.pid, signal.SIGKILL)
        out, _ = proc.communicate()
    seconds = time.monotonic() - started
    ran = RAN_RE.search(out or "")
    results = RESULT_RE.findall(out or "")
    return ModuleResult(
        name=name, rc=proc.returncode, ran=int(ran.group(1)) if ran else 0,
        ran_line=ran.group(0).split(" in ")[0] if ran else "", result_line=results[-1] if results else "",
        seconds=seconds, timed_out=timed_out, output=out or "")


def run_modules(names: list[str], *, tests_dir: Path, repo: Path, jobs: int, timeout_s: float,
                serial: frozenset, on_done=None) -> RunResult:
    """Run `names` once each: the pool first, the `serial` ones one at a time after it."""
    missing_serial = sorted(serial - set(names))
    if missing_serial:
        raise DiscoveryError("SERIAL_MODULES names that match no module: %s" % ", ".join(missing_serial))
    for name in names:
        if not (tests_dir / name).is_file():
            raise DiscoveryError("module %s vanished from %s" % (name, tests_dir))
    pooled = [n for n in names if n not in serial]
    tail = [n for n in names if n in serial]
    started = time.monotonic()
    done: list[ModuleResult] = []

    def one(name):
        res = run_one(name, tests_dir, repo, timeout_s)
        if on_done:
            on_done(res)
        return res

    with ThreadPoolExecutor(max_workers=max(1, jobs)) as pool:
        done.extend(pool.map(one, pooled))
    done.extend(one(n) for n in tail)
    done.sort(key=lambda m: m.name)
    return RunResult(modules=done, wall=time.monotonic() - started)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--tests-dir", type=Path, default=DEFAULT_TESTS_DIR)
    parser.add_argument("--repo", type=Path, default=REPO, help="working directory of every module")
    parser.add_argument("--jobs", type=int, default=os.cpu_count() or 1)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_S, help="seconds per module")
    args = parser.parse_args(argv)
    if args.jobs < 1 or args.timeout <= 0:
        print("usage: --jobs must be >= 1 and --timeout > 0", file=sys.stderr)
        return EXIT_USAGE
    try:
        names = discover_modules(args.tests_dir)
        if not names:
            raise DiscoveryError("no %s module found in %s" % (MODULE_GLOB, args.tests_dir))
        serial = frozenset(SERIAL_MODULES) & set(names) if args.tests_dir != DEFAULT_TESTS_DIR else frozenset(SERIAL_MODULES)
        result = run_modules(names, tests_dir=args.tests_dir, repo=args.repo, jobs=args.jobs,
                             timeout_s=args.timeout, serial=serial,
                             on_done=lambda m: print(m.line(), flush=True))
    except DiscoveryError as exc:
        print("DISCOVERY ERROR: %s" % exc, file=sys.stderr)
        return EXIT_USAGE
    print(result.summary(), flush=True)
    for m in result.modules:
        if m.bad:
            print("\n===== %s (rc=%s%s) =====" % (m.name, m.rc, ", TIMEOUT" if m.timed_out else ""))
            print(m.output)
    return EXIT_BAD_MODULE if result.bad else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
