#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Fixture proof for the #3546 release controls (Python port of test-release-hardening.sh).

release.yml is workflow_dispatch-only and publishes to crates.io, GHCR,
Homebrew and COPR, so its controls cannot be proven by "run a release and
see". This harness proves each one refuses what it exists to refuse, using
throwaway git repositories, canned GitHub API responses and PATH shims:

  A  structure   check-release-workflow.py passes on the live release.yml
                 and FAILS on the frozen pre-#3546 copy (R-203).
  B  tag         the preflight "Verify the tag" block, EXTRACTED VERBATIM
                 from release.yml, accepts an enrolled SSH-signed tag and
                 refuses a lightweight tag, an unsigned tag, a foreign-key
                 tag, a signed tag object re-pointed under another name and
                 an empty allowlist. R-203: the frozen pre-fix preflight
                 block ACCEPTS the lightweight tag.
  C  moved tag   the extracted "Re-assert the release tag has not moved"
                 block passes on an unmoved tag and refuses a tag that was
                 re-signed onto another commit or deleted after preflight.
  D  qualify     qualify-sha.py over canned check-runs: missing, skipped-only,
                 in-progress, failed-latest-attempt, foreign-app spoof and
                 non-gating-workflow spoof all refuse; skipped-plus-success
                 and failed-then-rerun-success pass; a required context on
                 page two is found through a stub `gh`, and a failed page
                 read refuses.
  E  ruleset     assert-tag-ruleset.sh accepts only an ACTIVE tag ruleset on
                 refs/tags/v* carrying both update and deletion rules.
  F  nfpm        the extracted "Download nfpm (pinned digest)" block (the
                 step that downloads and extracts the archive since the
                 round-6 split) refuses an altered nfpm tarball BEFORE tar
                 runs and extracts one that matches the pinned digest.
                 R-203: the frozen pre-fix "Build deb and rpm packages" block
                 pipes the altered bytes straight into tar.

Scratch lives under .local-runs/ (never a system temp directory).
Exit codes: 0 all cases behave, 1 a case misbehaved.
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
LIVE_YML = REPO_ROOT / ".github" / "workflows" / "release.yml"
FROZEN_YML = REPO_ROOT / "scripts" / "test" / "fixtures" / "release-yml-prefix-3546.yml"

FAILURES = []


def say(text):
    print(text, flush=True)


def passed(name):
    say("  ok    " + name)


def failed(name):
    FAILURES.append(name)
    print("  FAIL  " + name, file=sys.stderr, flush=True)


def tail(text, count=3):
    return " ".join(text.splitlines()[-count:])


def expect_rc(name, want, rc, out, needle=""):
    """want is 0 or "nonzero"; out is the captured output text."""
    if want == 0 and rc != 0:
        failed("%s: expected success, got rc=%d: %s" % (name, rc, tail(out)))
        return
    if want == "nonzero" and rc == 0:
        failed("%s: expected a refusal, got rc=0" % name)
        return
    if needle and needle not in out:
        failed("%s: output lacks '%s': %s" % (name, needle, tail(out)))
        return
    passed(name)


def extract_run(path, name):
    """The verbatim `run: |` body of the first step with that exact name, de-indented.

    Fails loudly if the step is missing so a renamed step can never make the
    harness test nothing."""
    want = "      - name: " + name
    body = []
    instep = False
    inrun = False
    for line in Path(path).read_text(encoding="utf-8").split("\n"):
        if not instep:
            if line == want:
                instep = True
            continue
        if not inrun:
            if line.startswith("      - "):
                break
            if line == "        run: |":
                inrun = True
            continue
        if line == "":
            body.append("")
        elif line.startswith("          "):
            body.append(line[10:])
        else:
            break
    if not body or not any(body):
        raise SystemExit("extract_run: no run block for step '%s' in %s" % (name, path))
    return "\n".join(body) + "\n"


def run(argv, cwd=None, env=None, check=False):
    """Run an argument list; return (rc, combined output)."""
    proc = subprocess.run(argv, cwd=None if cwd is None else str(cwd), env=env,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          universal_newlines=True)
    if check and proc.returncode != 0:
        raise SystemExit("setup failed: %s\n%s" % (" ".join(argv), proc.stdout))
    return proc.returncode, proc.stdout


def run_body(body, cwd, env_extra, path_prefix=None):
    """Run a step body through bash -euo pipefail -c, the way a GitHub step does."""
    env = dict(os.environ)
    if path_prefix:
        env["PATH"] = str(path_prefix) + os.pathsep + env.get("PATH", "")
    env.update(env_extra)
    return run(["bash", "-euo", "pipefail", "-c", body], cwd=cwd, env=env)


def git(cwd, *args, check=True, env=None):
    return run(["git"] + list(args), cwd=cwd, env=env, check=check)


def write_shim(path, source):
    path.write_text("#!/usr/bin/env python3\n" + source, encoding="utf-8")
    path.chmod(0o755)


# ---------------------------------------------------------------------------
def case_a(t):
    say("A  structure")
    checker = str(REPO_ROOT / "scripts" / "release" / "check-release-workflow.py")
    rc, out = run(["python3", checker, "--workflow", str(LIVE_YML),
                   "--signers", str(REPO_ROOT / "scripts/qc-allowlists/release-tag-signers.txt"),
                   "--enrolled", str(REPO_ROOT / "scripts/qc-allowlists/enrolled-commit-signers.txt")])
    if rc == 0:
        passed("live release.yml satisfies R1-R12")
    else:
        failed("live release.yml: " + out)
    rc, out = run(["python3", checker, "--workflow", str(FROZEN_YML)])
    if rc == 0:
        failed("R-203: the frozen pre-#3546 release.yml passed the structural check (the check is vacuous)")
        return
    missing = [r for r in ("R1:", "R2:", "R3:", "R5:", "R6:", "R7:", "R8:", "R9:", "R11:", "R12:")
               if "VIOLATION " + r not in out]
    if missing:
        failed("R-203: frozen release.yml did not trip: " + " ".join(missing))
    else:
        passed("R-203: frozen pre-#3546 release.yml trips R1 R2 R3 R5 R6 R7 R8 R9 R11 R12")


PRINCIPAL = "operator-fixture"  # the tagger identity and the allowed-signers principal of the throwaway keys


def case_b_c(t):
    say("B  tag verification (extracted preflight block)")
    run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(t / "op"), "-C", "op"], check=True)
    run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(t / "rogue"), "-C", "rogue"], check=True)
    remote = t / "remote.git"
    run(["git", "init", "-q", "--bare", str(remote)], check=True)
    author = t / "author"
    run(["git", "init", "-q", "-b", "main", str(author)], check=True)
    for key, value in (("user.name", "Operator"), ("user.email", PRINCIPAL), ("gpg.format", "ssh"),
                       ("user.signingkey", str(t / "op.pub")), ("commit.gpgsign", "false"),
                       ("tag.gpgsign", "false")):
        git(author, "config", key, value)
    (author / "f").write_text("one\n", encoding="utf-8")
    git(author, "add", "f")
    git(author, "commit", "-q", "-m", "one")
    git(author, "tag", "-s", "v1.0.0", "-m", "signed release")
    git(author, "tag", "v1.0.1")
    git(author, "tag", "-a", "v1.0.2", "-m", "annotated, unsigned")
    git(author, "-c", "user.signingkey=%s" % (t / "rogue.pub"), "tag", "-s", "v1.0.3", "-m", "foreign key")
    git(author, "update-ref", "refs/tags/v1.0.9", git(author, "rev-parse", "refs/tags/v1.0.0")[1].strip())
    git(author, "remote", "add", "origin", str(remote))
    git(author, "push", "-q", "origin", "main", "--tags")

    # The trusted tooling checkout: the live scripts plus an allowlist holding
    # only the fixture's operator key, at the path release.yml passes.
    trusted = t / "trusted"
    run(["git", "clone", "-q", str(remote), str(trusted)])
    (trusted / "scripts" / "release").mkdir(parents=True)
    (trusted / "scripts" / "qc-allowlists").mkdir(parents=True)
    for sh in sorted((REPO_ROOT / "scripts" / "release").glob("*.sh")):
        shutil.copy(str(sh), str(trusted / "scripts" / "release" / sh.name))
    pub = (t / "op.pub").read_text(encoding="utf-8").split()
    signers = trusted / "scripts" / "qc-allowlists" / "release-tag-signers.txt"
    signers.write_text("%s %s %s\n" % (PRINCIPAL, pub[0], pub[1]), encoding="utf-8")

    verify = extract_run(LIVE_YML, "Verify the tag (annotated, SSH-signed by an enrolled release key)")
    gh_output = t / "gh_output"

    def run_verify(tag):
        gh_output.write_text("", encoding="utf-8")
        return run_body(verify, trusted, {"TAG": tag, "GITHUB_OUTPUT": str(gh_output)})

    rc, out = run_verify("v1.0.0")
    expect_rc("enrolled SSH-signed annotated tag is accepted", 0, rc, out, "verify-tag: OK")
    want_sha = git(author, "rev-parse", "v1.0.0^{commit}")[1].strip()
    want_obj = git(author, "rev-parse", "v1.0.0")[1].strip()
    outputs = gh_output.read_text(encoding="utf-8").split("\n")
    if ("sha=" + want_sha) in outputs and ("tag_object=" + want_obj) in outputs:
        passed("preflight exports the verified sha and tag object")
    else:
        failed("preflight outputs wrong: " + " ".join(outputs))
    rc, out = run_verify("v1.0.1")
    expect_rc("lightweight tag is refused", "nonzero", rc, out, "lightweight tag")
    rc, out = run_verify("v1.0.2")
    expect_rc("annotated but unsigned tag is refused", "nonzero", rc, out, "no SSH signature")
    rc, out = run_verify("v1.0.3")
    expect_rc("tag signed by a key not in the allowlist is refused", "nonzero", rc, out, "does not verify")
    rc, out = run_verify("v1.0.9")
    expect_rc("signed tag object re-pointed under another name is refused", "nonzero", rc, out, "names itself")

    verify_tag = str(REPO_ROOT / "scripts" / "release" / "verify-tag.sh")
    rc6, out6 = run(["bash", verify_tag, "--repo", str(trusted), "--tag", "v1.0", "--signers", str(signers)])
    empty = t / "empty-signers"
    empty.write_text("# no keys\n", encoding="utf-8")
    rc7, out7 = run(["bash", verify_tag, "--repo", str(trusted), "--tag", "v1.0.0", "--signers", str(empty)])
    expect_rc("non-SemVer tag name is refused", "nonzero", rc6, out6, "does not match SemVer")
    expect_rc("an allowlist with no keys refuses everything", "nonzero", rc7, out7, "zero enrolled keys")

    # R-203: the frozen pre-fix preflight accepts the lightweight tag.
    old = extract_run(FROZEN_YML, "Resolve tag + sha + prerelease flag")
    gh_output.write_text("", encoding="utf-8")
    rc, out = run_body("git fetch -q origin 'refs/tags/*:refs/tags/*' && bash -euo pipefail -c \"$OLD\"",
                       trusted, {"OLD": old, "TAG": "v1.0.1", "GITHUB_OUTPUT": str(gh_output)})
    if rc == 0:
        passed("R-203: the frozen pre-#3546 preflight ACCEPTS a lightweight tag")
    else:
        failed("R-203: the frozen preflight refused the lightweight tag (fixture no longer reproduces the defect): " + out)

    say("C  moved tag (extracted re-assert block)")
    reassert = extract_run(LIVE_YML, "Re-assert the release tag has not moved (#3546)")

    def run_reassert():
        return run_body(reassert, trusted, {"REMOTE": str(remote), "TAG": "v1.0.0",
                                            "TAG_OBJECT": want_obj, "SHA": want_sha})

    rc, out = run_reassert()
    expect_rc("an unmoved tag passes the re-assert", 0, rc, out, "assert-tag-unmoved: OK")
    (author / "f").write_text("two\n", encoding="utf-8")
    git(author, "commit", "-q", "-am", "two")
    git(author, "tag", "-f", "-s", "v1.0.0", "-m", "re-signed onto another commit")
    git(author, "push", "-q", "-f", "origin", "refs/tags/v1.0.0")
    rc, out = run_reassert()
    expect_rc("a tag re-signed onto another commit after preflight is refused", "nonzero", rc, out,
              "the tag moved after verification")
    git(author, "push", "-q", "origin", ":refs/tags/v1.0.0")
    rc, out = run_reassert()
    expect_rc("a tag deleted after preflight is refused", "nonzero", rc, out, "no longer exists")


STUB_GH = '''import os, re, sys
url = sys.argv[2]
with open(os.environ["STUB_LOG"], "a") as fh:
    fh.write(url + "\\n")
match = re.search(r"[?&]page=([0-9]*)", url)
page = match.group(1) if match else ""
if "/check-runs" in url:
    kind = "check-runs"
elif "/actions/runs" in url:
    kind = "runs"
else:
    sys.exit(9)
if os.environ.get("STUB_FAIL_PAGE") and kind == "check-runs" and page == os.environ["STUB_FAIL_PAGE"]:
    sys.stderr.write("HTTP 502\\n")
    sys.exit(1)
path = os.path.join(os.environ["STUB_DIR"], "page-%s-%s.json" % (kind, page))
if os.path.isfile(path):
    sys.stdout.write(open(path).read())
else:
    sys.stdout.write('{"total_count":0,"check_runs":[],"workflow_runs":[]}\\n')
'''


def case_d(t):
    say("D  qualify")
    sha = "1" * 40
    (t / "contexts").write_text("# fixture mirror\nCtx A\nCtx B\n", encoding="utf-8")
    app = {"slug": "github-actions", "id": 15368}

    def wrun(suite, path, event="push"):
        return {"id": suite * 10, "check_suite_id": suite, "path": ".github/workflows/" + path,
                "event": event, "head_sha": sha}

    def cr(name, suite, conclusion, started="2026-09-11T10:00:00Z", status="completed", app=app, cid=None):
        # A stable id: the old harness used hash(), which varies per process.
        stable = int(hashlib.sha256(("%s|%s|%s" % (name, suite, started)).encode()).hexdigest()[:6], 16)
        return {"id": cid or stable, "name": name, "head_sha": sha, "status": status,
                "conclusion": conclusion if status == "completed" else None, "started_at": started,
                "app": app, "check_suite": {"id": suite}}

    cases = {
        "pass": ([cr("Ctx A", 1, "success"), cr("Ctx B", 1, "success")], [wrun(1, "ci.yml")]),
        "missing": ([cr("Ctx A", 1, "success")], [wrun(1, "ci.yml")]),
        "skipped_only": ([cr("Ctx A", 1, "success"), cr("Ctx B", 1, "skipped")], [wrun(1, "ci.yml")]),
        "skip_plus_ok": ([cr("Ctx A", 1, "success"), cr("Ctx B", 1, "skipped"), cr("Ctx B", 2, "success")],
                         [wrun(1, "ci.yml"), wrun(2, "ci.yml", "pull_request")]),
        "rerun_failed": ([cr("Ctx A", 1, "success"), cr("Ctx B", 1, "success", "2026-09-11T10:00:00Z"),
                          cr("Ctx B", 1, "failure", "2026-09-11T11:00:00Z")], [wrun(1, "ci.yml")]),
        "rerun_fixed": ([cr("Ctx A", 1, "success"), cr("Ctx B", 1, "failure", "2026-09-11T10:00:00Z"),
                         cr("Ctx B", 1, "success", "2026-09-11T11:00:00Z")], [wrun(1, "ci.yml")]),
        "other_run_fail": ([cr("Ctx A", 1, "success"), cr("Ctx B", 1, "success"), cr("Ctx B", 2, "failure")],
                           [wrun(1, "ci.yml"), wrun(2, "ci.yml", "pull_request")]),
        "in_progress": ([cr("Ctx A", 1, "success"), cr("Ctx B", 1, None, status="in_progress")],
                        [wrun(1, "ci.yml")]),
        "foreign_app": ([cr("Ctx A", 1, "success"),
                         cr("Ctx B", 1, "success", app={"slug": "evil-app", "id": 1})], [wrun(1, "ci.yml")]),
        "wrong_carrier": ([cr("Ctx A", 1, "success"), cr("Ctx B", 3, "success")],
                          [wrun(1, "ci.yml"), wrun(3, "evil.yml")]),
    }
    for name, (crs, runs) in cases.items():
        (t / ("q-%s-cr.json" % name)).write_text(json.dumps({"total_count": len(crs), "check_runs": crs}))
        (t / ("q-%s-wr.json" % name)).write_text(json.dumps({"total_count": len(runs), "workflow_runs": runs}))
    # Pagination fixture: page 1 is 100 unrelated check-runs, page 2 carries both contexts.
    filler = [cr("Other %d" % i, 1, "success", cid=100000 + i) for i in range(100)]
    (t / "page-check-runs-1.json").write_text(json.dumps({"total_count": 102, "check_runs": filler}))
    (t / "page-check-runs-2.json").write_text(json.dumps(
        {"total_count": 102, "check_runs": [cr("Ctx A", 1, "success"), cr("Ctx B", 1, "success")]}))
    (t / "page-runs-1.json").write_text(json.dumps({"total_count": 1, "workflow_runs": [wrun(1, "ci.yml")]}))

    qualify = str(REPO_ROOT / "scripts" / "release" / "qualify-sha.py")

    def q(case):
        return run(["python3", qualify, "--sha", sha, "--contexts", str(t / "contexts"), "--carriers", "ci.yml",
                    "--check-runs", str(t / ("q-%s-cr.json" % case)),
                    "--workflow-runs", str(t / ("q-%s-wr.json" % case))])

    table = (
        ("pass", 0, "every context succeeded: qualified", "qualify-sha: OK"),
        ("missing", "nonzero", "a context with no check-run refuses", "no check-run"),
        ("skipped_only", "nonzero", "a skipped-only context refuses", "never ran to success"),
        ("skip_plus_ok", 0, "a skipped run does not veto a success from another run", "qualify-sha: OK"),
        ("rerun_failed", "nonzero", "a re-run that failed is not masked by the earlier success", "failure"),
        ("rerun_fixed", 0, "a re-run that succeeded supersedes the earlier failure", "qualify-sha: OK"),
        ("other_run_fail", "nonzero", "a failure in another run vetoes", "failure"),
        ("in_progress", "nonzero", "an in-progress context refuses", "incomplete:in_progress"),
        ("foreign_app", "nonzero", "a same-named check-run from another app is not counted", "no check-run"),
        ("wrong_carrier", "nonzero", "a same-named check-run from a non-gating workflow is not counted",
         "no check-run"),
    )
    for case, want, name, needle in table:
        rc, out = q(case)
        expect_rc(name, want, rc, out, needle)

    # --fetch through a stub `gh`: explicit pagination, and a failed page read.
    (t / "bin").mkdir()
    write_shim(t / "bin" / "gh", STUB_GH)
    fetch = ["python3", qualify, "--fetch", "--repo", "o/r", "--sha", sha, "--contexts", str(t / "contexts"),
             "--carriers", "ci.yml"]
    env = {"STUB_DIR": str(t), "STUB_LOG": str(t / "gh.log")}
    full = dict(os.environ)
    full["PATH"] = str(t / "bin") + os.pathsep + full.get("PATH", "")
    full.update(env)
    rc, out = run(fetch, env=full)
    full_fail = dict(full)
    full_fail.update({"STUB_LOG": str(t / "gh-fail.log"), "STUB_FAIL_PAGE": "2"})
    rc_fail, out_fail = run(fetch, env=full_fail)
    expect_rc("contexts on page two are found through explicit pagination", 0, rc, out, "qualify-sha: OK")
    log = (t / "gh.log").read_text(encoding="utf-8") if (t / "gh.log").exists() else ""
    if "commits/%s/check-runs?filter=all&per_page=100&page=2" % sha in log:
        passed("the API is queried by SHA (never tag), filter=all, per_page=100, page 2 read")
    else:
        failed("unexpected API URLs: " + " ".join(log.split()))
    expect_rc("a failed page read refuses instead of qualifying on a partial read", "nonzero", rc_fail, out_fail,
              "failed")


def case_e(t):
    say("E  tag ruleset")
    good = ('{"id":7,"name":"release-tags","target":"tag","enforcement":"active","conditions":{"ref_name":'
            '{"include":["refs/tags/v*"]}},"rules":[{"type":"update"},{"type":"deletion"},{"type":"creation"}]}')

    def mk_rules(name, listing, detail):
        d = t / name
        d.mkdir()
        (d / "list.json").write_text(listing, encoding="utf-8")
        (d / "7.json").write_text(detail, encoding="utf-8")
        return d

    tag_list = '[{"id":7,"target":"tag","enforcement":"active"}]'
    dirs = {
        "none": mk_rules("r-none", '[{"id":1,"target":"branch","enforcement":"active"}]', "{}"),
        "good": mk_rules("r-good", tag_list, good),
        "eval": mk_rules("r-eval", '[{"id":7,"target":"tag","enforcement":"evaluate"}]',
                         good.replace("active", "evaluate", 1)),
        "nodel": mk_rules("r-nodel", tag_list, good.replace('{"type":"deletion"},', "", 1)),
        "scope": mk_rules("r-scope", tag_list, good.replace("refs/tags/v*", "refs/tags/other*", 1)),
    }
    script = str(REPO_ROOT / "scripts" / "release" / "assert-tag-ruleset.sh")

    def rs(key):
        return run(["bash", script, "--from-dir", str(dirs[key])])

    rc, out = rs("good")
    expect_rc("an active v* tag ruleset with update+deletion is accepted", 0, rc, out, "assert-tag-ruleset: OK")
    for key, name in (("none", "no tag ruleset refuses"),
                      ("eval", "an evaluate-mode (not enforced) ruleset refuses"),
                      ("nodel", "a ruleset without a deletion rule refuses"),
                      ("scope", "a ruleset not scoped to refs/tags/v* refuses")):
        rc, out = rs(key)
        expect_rc(name, "nonzero", rc, out, "REFUSED")


SHIM_CURL = '''import sys
# shim curl: serve ALTERED bytes, to -o FILE when given, else to stdout.
args = sys.argv[1:]
out = ""
i = 0
while i < len(args):
    if args[i] == "-o":
        out = args[i + 1]
        i += 2
    else:
        i += 1
data = b"not the nfpm release tarball\\n"
if out:
    open(out, "wb").write(data)
else:
    sys.stdout.buffer.write(data)
'''

SHIM_TAR = '''import os, sys
# shim tar: record that extraction happened; never touch /usr/local/bin.
try:
    sys.stdin.buffer.read()
except Exception:
    pass
open(os.environ["TAR_MARK"], "w").close()
'''

SHIM_NFPM = '''import os
# shim nfpm: pretend to package.
open(os.path.join("dist", "x.deb"), "w").close()
open(os.path.join("dist", "x.rpm"), "w").close()
'''

ALTERED = b"not the nfpm release tarball\n"


def case_f(t):
    say("F  nfpm archive (extracted download block)")
    fbin = t / "fbin"
    fbin.mkdir()
    (t / "rt").mkdir()
    (t / "pkg" / "dist").mkdir(parents=True)
    write_shim(fbin / "curl", SHIM_CURL)
    write_shim(fbin / "tar", SHIM_TAR)
    write_shim(fbin / "nfpm", SHIM_NFPM)

    # Since the round-6 split the live "Build deb and rpm packages" step only
    # runs `nfpm package`; the download, the digest check and the extraction
    # are in "Download nfpm (pinned digest)", so that is the step under test.
    live = extract_run(LIVE_YML, "Download nfpm (pinned digest)")
    # GitHub renders `${{ matrix.nfpm_arch }}` before the shell sees the block;
    # the frozen block carries it, render it the same way here.
    old = extract_run(FROZEN_YML, "Build deb and rpm packages").replace("${{ matrix.nfpm_arch }}", "amd64")

    mark_live = t / "tar-live"
    rc, out = run_body(live, t / "pkg", {"TAR_MARK": str(mark_live), "RUNNER_TEMP": str(t / "rt"),
                                         "RUNNER_ARCH": "X64", "TAG": "v1.0.0"}, fbin)
    if rc != 0 and not mark_live.exists():
        passed("an altered nfpm tarball is refused before tar runs")
    else:
        failed("altered nfpm tarball: rc=%d, tar ran=%s: %s" % (rc, "yes" if mark_live.exists() else "no", tail(out)))

    # Control: the same block with the pinned X64 digest replaced by the digest
    # of the served bytes must extract, so the refusal above is the digest check
    # and not a broken harness.
    pinned = re.search(r"X64\)\s+NFPM_ARCH=x86_64; NFPM_SHA256=([0-9a-f]{64})", live)
    if pinned is None:
        failed("the live download block no longer pins an X64 digest the harness can read")
    else:
        control = live.replace(pinned.group(1), hashlib.sha256(ALTERED).hexdigest())
        mark_ctl = t / "tar-control"
        rc, out = run_body(control, t / "pkg", {"TAR_MARK": str(mark_ctl), "RUNNER_TEMP": str(t / "rt"),
                                                "RUNNER_ARCH": "X64", "TAG": "v1.0.0"}, fbin)
        if rc == 0 and mark_ctl.exists():
            passed("a nfpm tarball that matches the pinned digest is extracted")
        else:
            failed("control with the matching digest: rc=%d, tar ran=%s: %s"
                   % (rc, "yes" if mark_ctl.exists() else "no", tail(out)))

    mark_old = t / "tar-old"
    rc_old, out_old = run_body(old, t / "pkg", {"TAR_MARK": str(mark_old), "TAG": "v1.0.0"}, fbin)
    if rc_old == 0 and mark_old.exists():
        passed("R-203: the frozen pre-#3546 block extracts the altered archive and packages it")
    else:
        failed("R-203: the frozen nfpm block no longer reproduces the defect (rc=%d): %s" % (rc_old, tail(out_old)))


def main(argv=None):
    parser = argparse.ArgumentParser(description="Fixture proof for the #3546 release controls.")
    parser.parse_args(argv)
    scratch = REPO_ROOT / ".local-runs" / ("test-release-hardening.%d" % os.getpid())
    scratch.mkdir(parents=True)
    try:
        case_a(scratch)
        case_b_c(scratch)
        case_d(scratch)
        case_e(scratch)
        case_f(scratch)
    finally:
        shutil.rmtree(str(scratch), ignore_errors=True)
    if FAILURES:
        print("test-release-hardening: FAIL — %d case(s) misbehaved" % len(FAILURES), file=sys.stderr)
        return 1
    say("test-release-hardening: OK — every #3546 release control refuses what it exists to refuse, "
        "and the frozen pre-fix workflow is shown to accept it")
    return 0


if __name__ == "__main__":
    sys.exit(main())
