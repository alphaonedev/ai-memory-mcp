"""ci-gate: fold the `toJSON(needs)` of the aggregate job into one verdict (#8240).

Usage:
    python3 -I scripts/ci/impact/gate.py --needs <json | @file> \
        [--github-ref <ref>] [--rules rules.json]

Fail closed. A job that succeeded passes. A SKIPPED job passes only when
  - `classify` succeeded and recorded docs_only 'true' (the gated jobs carry
    that condition themselves), or
  - `select` succeeded AND its recorded output for the job's domain is the
    literal 'false', or
  - the ref is a version tag and the job is listed in rules.json
    tag_skip_jobs.
Every other outcome fails: failure, cancelled, timed_out, an unknown or
missing result, a skip while `select` failed, was cancelled or skipped, a skip
with an empty, missing or malformed domain output. A job with no key in
rules.json job_map (select, classify, build-script-vetting) must succeed.
A job of REQUIRED_NEEDS that is absent from the needs payload fails the gate
with the fixed reason `missing-needed-job` naming the job.
decision: the gate requires the full expected job set over tolerating an
absent job because an absent result is indistinguishable from a skipped gate
Exit 0 only when every job passed.
"""
import argparse
import json
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

# >>> sibling-load 9399 (canonical text; scripts/ci/sibling_load.py; test_sibling_load_9399 pins every copy)
class SiblingLoadError(ImportError):
    """A refused sibling load; ``reason`` is one of the fixed words the refusal line prints."""

    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def _sibling_path(filename):
    import os
    return os.path.join(os.path.dirname(os.path.realpath(__file__)), filename)


def _load_sibling(filename, module_name):
    import os
    import stat
    import sys
    import types
    here = os.path.dirname(os.path.realpath(__file__))
    try:
        here_st = os.stat(here)
    except OSError:
        raise SiblingLoadError("unreadable") from None
    here_id = (here_st.st_dev, here_st.st_ino)
    path = os.path.realpath(os.path.join(here, filename))
    if os.path.commonpath([here, path]) != here:
        raise SiblingLoadError("symlink leaves the script folder")
    loaded = sys.modules.get(module_name)
    if loaded is not None:
        if os.path.realpath(getattr(loaded, "__file__", None) or "") == path:
            return loaded
        raise SiblingLoadError("module name taken")
    # The script folder opened must have the device and inode the stat above recorded, so a swap of that folder or of
    # any folder above it (for a symlink or by a rename) is refused; each component below it is opened relative to the
    # descriptor before it and never through a symlink; the type check, the read and the compile use one descriptor.
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    dir_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | nofollow
    parts = os.path.relpath(path, here).split(os.sep)
    fds = []
    try:
        try:
            fds.append(os.open(here, dir_flags))
            opened = os.fstat(fds[0])
            if (opened.st_dev, opened.st_ino) != here_id:
                raise SiblingLoadError("unreadable")
            for part in parts[:-1]:
                fds.append(os.open(part, dir_flags, dir_fd=fds[-1]))
            fds.append(os.open(parts[-1], os.O_RDONLY | nofollow | getattr(os, "O_NONBLOCK", 0), dir_fd=fds[-1]))
        except FileNotFoundError:
            raise SiblingLoadError("absent") from None
        except OSError:
            raise SiblingLoadError("unreadable") from None
        try:
            if not stat.S_ISREG(os.fstat(fds[-1]).st_mode):
                raise SiblingLoadError("not a regular file")
            with os.fdopen(fds[-1], "rb", closefd=False) as handle:
                source = handle.read()
        except OSError:
            raise SiblingLoadError("unreadable") from None
    finally:
        for fd in fds:
            os.close(fd)
    if not source:
        raise SiblingLoadError("empty")
    module = types.ModuleType(module_name)
    module.__file__ = path
    saved_path = list(sys.path)
    sys.modules[module_name] = module
    try:
        exec(compile(source, path, "exec"), module.__dict__)
    except BaseException:
        sys.modules.pop(module_name, None)
        raise
    finally:
        sys.path[:] = saved_path
    return module


def _sibling_refusal(prog, filename, exc):
    import sys
    why = exc.reason if isinstance(exc, SiblingLoadError) else type(exc).__name__
    if not why.replace(" ", "_").isidentifier():
        why = "BaseException"
    # The path comes from the checkout, so a control character in a folder name must not start a second output line
    # (a runner reads workflow commands at a line start): every non-printable character is written as its escape.
    shown = "".join(ch if ch.isprintable() else ascii(ch)[1:-1] for ch in _sibling_path(filename))
    print("%s: refused: sibling module %s at %s cannot be loaded (%s)" % (prog, filename, shown, why),
          file=sys.stderr, flush=True)
# <<< sibling-load 9399


SIBLING_PROG = "gate"
SIBLING_EXIT_LOAD_REFUSED = 3

try:
    common = _load_sibling("common.py", "impact.common")
except (Exception, SystemExit) as exc:  # any failed load ends here with one fixed line (#9399)
    _sibling_refusal(SIBLING_PROG, "common.py", exc)
    sys.exit(SIBLING_EXIT_LOAD_REFUSED)

RESULT_SUCCESS = "success"
RESULT_SKIPPED = "skipped"
FILE_PREFIX = "@"
SELECT_JOB = "select"
CLASSIFY_JOB = "classify"
DOMAIN_FALSE = "false"
DOCS_ONLY_KEY = "docs_only"
DOCS_ONLY_TRUE = "true"
TAG_REF_PREFIX = "refs/tags/v"
MISSING_REASON = "missing-needed-job"
# The `needs:` list of the ci-gate job in .github/workflows/ci.yml; a test
# keeps the two in step.
REQUIRED_NEEDS = ("select", "classify", "build-script-vetting", "check",
                  "mobile-cross-compile")


def outputs_of(needs: dict, job: str) -> dict:
    """Return the outputs object of `job` (empty when absent or malformed)."""
    outputs = (needs.get(job) or {}).get("outputs")
    return outputs if isinstance(outputs, dict) else {}


def result_of(needs: dict, job: str) -> Optional[str]:
    """Return the result string of `job`, or None."""
    return (needs.get(job) or {}).get("result")


def skip_allowed(needs: dict, job: str, key: Optional[str], github_ref: str,
                 tag_skip_jobs: Iterable[str]) -> bool:
    """Return True when a skipped `job` is a legitimate, recorded skip."""
    if key is None:
        return False
    if (result_of(needs, CLASSIFY_JOB) == RESULT_SUCCESS
            and outputs_of(needs, CLASSIFY_JOB).get(DOCS_ONLY_KEY) == DOCS_ONLY_TRUE):
        return True
    if github_ref.startswith(TAG_REF_PREFIX) and job in set(tag_skip_jobs):
        return True
    return (result_of(needs, SELECT_JOB) == RESULT_SUCCESS
            and outputs_of(needs, SELECT_JOB).get(key) == DOMAIN_FALSE)


def evaluate(needs: dict, job_map: Dict[str, str], github_ref: str = "",
             tag_skip_jobs: Iterable[str] = (),
             required: Iterable[str] = ()) -> Tuple[bool, List[dict]]:
    """Return (ok, rows) for a needs document; every `required` job must be present."""
    rows: List[dict] = []
    ok = True
    tag_skip = list(tag_skip_jobs)
    for job in sorted(set(required) - set(needs)):
        ok = False
        rows.append({"job": job, "result": MISSING_REASON, "selected": True,
                     "ok": False})
    for job in sorted(needs):
        result = result_of(needs, job)
        key = job_map.get(job)
        excused = skip_allowed(needs, job, key, github_ref, tag_skip)
        if result == RESULT_SUCCESS:
            passed = True
        elif result == RESULT_SKIPPED:
            passed = excused
        else:
            passed = False
        ok = ok and passed
        rows.append({"job": job, "result": result, "selected": not excused,
                     "ok": passed})
    return ok, rows


def render(rows: List[dict]) -> str:
    """Render the verdict table."""
    width = max([len(r["job"]) for r in rows] + [3])
    lines = ["%-*s  %-10s  %-8s  %s" % (width, "job", "result", "selected", "ok")]
    for row in rows:
        lines.append("%-*s  %-10s  %-8s  %s" % (
            width, row["job"], row["result"], "yes" if row["selected"] else "no",
            "pass" if row["ok"] else "FAIL"))
    return "\n".join(lines)


def read_needs(arg: str) -> dict:
    """Parse the --needs argument (JSON text, or @path to a JSON file)."""
    text = Path(arg[len(FILE_PREFIX):]).read_text() if arg.startswith(FILE_PREFIX) else arg
    doc = json.loads(text)
    if not isinstance(doc, dict):
        raise ValueError("needs must be a JSON object")
    return doc


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--needs", required=True)
    parser.add_argument("--github-ref", default="", help="github.ref of the run")
    parser.add_argument("--rules", help="alternative rules.json")
    args = parser.parse_args(argv)
    try:
        needs = read_needs(args.needs)
        rules = common.load_rules(Path(args.rules) if args.rules else None)
        job_map = rules["job_map"]
        tag_skip_jobs = rules.get("tag_skip_jobs", [])
    except (ValueError, OSError, KeyError) as exc:
        common.log("gate: unusable input: %s" % exc)
        return common.EXIT_USAGE
    ok, rows = evaluate(needs, job_map, args.github_ref, tag_skip_jobs, REQUIRED_NEEDS)
    print(render(rows))
    for row in rows:
        if row["result"] == MISSING_REASON:
            print("ci-gate: %s: %s" % (MISSING_REASON, row["job"]))
    print("ci-gate: %s" % ("pass" if ok else "FAIL"))
    return common.EXIT_OK if ok else common.EXIT_FAIL


if __name__ == "__main__":
    sys.exit(main())
