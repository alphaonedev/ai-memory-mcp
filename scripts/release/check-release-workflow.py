#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""check-release-workflow.py — structural invariants of release.yml (#3546).

The release scripts (verify-tag.sh, qualify-sha.py, assert-tag-unmoved.sh,
assert-tag-ruleset.sh) are proven by fixtures, but a fixture proves a SCRIPT,
not that the workflow still calls it. A release.yml that stopped calling the
verifier, checked out the tag name again, dropped `qualify` from a job's
`needs`, or went back to `curl | tar` would leave every fixture green. These
checks read the workflow itself:

  R1  every actions/checkout of THIS repository pins `ref:`; in preflight and
      qualify it is `${{ github.sha }}` (the trusted tooling), everywhere else
      `${{ needs.preflight.outputs.sha }}`. A checkout with no `ref:` builds
      whatever the dispatch branch holds, so it is a violation too.
  R2  no `ref:` names `needs.preflight.outputs.tag` (the #3546 acceptance grep).
  R3  every job other than preflight and qualify lists `qualify` directly in
      `needs:`.
  R4  no `always()`, `cancelled()` or `failure()` anywhere: each would let a
      job run after qualify refused.
  R5  preflight runs scripts/release/verify-tag.sh against
      scripts/qc-allowlists/release-tag-signers.txt, exports `sha` and
      `tag_object` from that step, refuses a non-release dispatch ref, checks
      ancestry, and runs assert-tag-ruleset.sh.
  R6  qualify runs qualify-sha.py with the required-contexts mirror and
      `--carriers-from scripts/check-required-contexts.sh`.
  R7  every softprops/action-gh-release step is preceded, in the same job, by
      a step that runs assert-tag-unmoved.sh.
  R8  nothing is piped from curl into tar, and the nfpm download is checked
      with `sha256sum -c` against a pinned digest.
  R9  every `cargo install` (release.yml and the republish workflow) pins
      `--version`.
  R10 every key line in release-tag-signers.txt appears verbatim in
      enrolled-commit-signers.txt, and the file is not empty.

Usage: check-release-workflow.py --workflow F [--republish F]
                                 [--signers F --enrolled F]
Exit codes: 0 clean · 1 violations · 2 usage.
"""

from __future__ import annotations

import argparse
import re
import sys

TRUSTED_JOBS = {"preflight", "qualify"}
SHA_REF = "${{ needs.preflight.outputs.sha }}"
TRUSTED_REF = "${{ github.sha }}"


def split_jobs(text: str) -> dict[str, list[str]]:
    """Map job id -> its lines, from the top-level `jobs:` block."""
    lines = text.split("\n")
    try:
        start = lines.index("jobs:")
    except ValueError:
        return {}
    jobs: dict[str, list[str]] = {}
    current = None
    for line in lines[start + 1 :]:
        m = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
        if m:
            current = m.group(1)
            jobs[current] = []
            continue
        if line and not line.startswith(" ") and not line.startswith("#"):
            break
        if current is not None:
            jobs[current].append(line)
    return jobs


def split_steps(job_lines: list[str]) -> list[list[str]]:
    steps: list[list[str]] = []
    current: list[str] | None = None
    for line in job_lines:
        if re.match(r"^      - ", line):
            current = [line]
            steps.append(current)
        elif current is not None:
            if line and not line.startswith("       ") and not line.startswith("#"):
                current = None
                continue
            current.append(line)
    return steps


def needs_of(job_lines: list[str]) -> list[str]:
    for line in job_lines:
        m = re.match(r"^    needs:\s*(.*)$", line)
        if m:
            raw = m.group(1).strip()
            if raw.startswith("["):
                return [n.strip() for n in raw.strip("[]").split(",") if n.strip()]
            return [raw]
    return []


def step_text(step: list[str]) -> str:
    return "\n".join(step)


def check(workflow: str, republish: str | None, signers: str | None, enrolled: str | None) -> list[str]:
    v: list[str] = []
    text = open(workflow, encoding="utf-8").read()
    jobs = split_jobs(text)
    if "preflight" not in jobs or "qualify" not in jobs:
        v.append("R5/R6: release.yml must define both a `preflight` and a `qualify` job")

    for job, jlines in jobs.items():
        steps = split_steps(jlines)
        for step in steps:
            body = step_text(step)
            if "uses: actions/checkout@" not in body:
                continue
            if re.search(r"^\s+repository:", body, re.M):
                continue  # a different repository (e.g. the Homebrew tap)
            ref = re.search(r"^\s+ref:\s*(.+?)\s*$", body, re.M)
            want = TRUSTED_REF if job in TRUSTED_JOBS else SHA_REF
            if not ref:
                v.append(f"R1: job `{job}` has an actions/checkout with no `ref:` (it would build the dispatch branch, not the verified commit)")
            elif ref.group(1) != want:
                v.append(f"R1: job `{job}` checks out `{ref.group(1)}`, expected `{want}`")
        if job not in TRUSTED_JOBS and "qualify" not in needs_of(jlines):
            v.append(f"R3: job `{job}` does not list `qualify` in `needs:` (it could run on an unqualified commit)")
        for i, step in enumerate(steps):
            if "softprops/action-gh-release@" in step_text(step):
                if not any("scripts/release/assert-tag-unmoved.sh" in step_text(s) for s in steps[:i]):
                    v.append(f"R7: job `{job}` uploads to the GitHub release without first running assert-tag-unmoved.sh")

    for line in text.split("\n"):
        if re.match(r"^\s+ref:.*needs\.preflight\.outputs\.tag", line):
            v.append(f"R2: checkout by tag name: `{line.strip()}`")
    # Comments may legitimately mention a banned shape (to explain why it is
    # banned); only code lines count.
    code = "\n".join(l for l in text.split("\n") if not l.strip().startswith("#"))
    for token in ("always()", "cancelled()", "failure()"):
        if token in code:
            v.append(f"R4: `{token}` appears in release.yml (a job could run after qualify refused)")

    def code_of(job: str) -> str:
        return "\n".join(l for l in jobs.get(job, []) if not l.strip().startswith("#"))

    pre = code_of("preflight")
    for needle, what in (
        ("scripts/release/verify-tag.sh", "run verify-tag.sh"),
        ("--signers scripts/qc-allowlists/release-tag-signers.txt", "verify against release-tag-signers.txt"),
        ("sha: ${{ steps.verify.outputs.sha }}", "export `sha` from the verify step"),
        ("tag_object: ${{ steps.verify.outputs.tag_object }}", "export `tag_object` from the verify step"),
        ("refs/heads/release/*", "refuse a dispatch from anything but a release branch"),
        ("git merge-base --is-ancestor", "require the tagged commit to be on the dispatch branch"),
        ("scripts/release/assert-tag-ruleset.sh", "require the v* tag ruleset"),
    ):
        if needle not in pre:
            v.append(f"R5: preflight does not {what}")
    qual = code_of("qualify")
    for needle in (
        "scripts/release/qualify-sha.py",
        "--contexts scripts/qc-allowlists/required-contexts-release.txt",
        "--carriers-from scripts/check-required-contexts.sh",
    ):
        if needle not in qual:
            v.append(f"R6: qualify does not pass `{needle}`")

    if re.search(r"curl[^\n]*\|\s*tar\b", code):
        v.append("R8: a download is piped straight from curl into tar")
    if "nfpm" in code and not re.search(r"sha256sum -c", code):
        v.append("R8: the nfpm download is not checked with `sha256sum -c` against a pinned digest")

    for path in [workflow] + ([republish] if republish else []):
        for line in open(path, encoding="utf-8").read().split("\n"):
            if re.search(r"\bcargo install\b", line) and "--version" not in line and not line.strip().startswith("#"):
                v.append(f"R9: unpinned `cargo install` in {path}: `{line.strip()}`")

    if signers and enrolled:
        def keylines(p):
            out = []
            for raw in open(p, encoding="utf-8"):
                s = raw.strip()
                if s and not s.startswith("#"):
                    out.append(s)
            return out
        rel = keylines(signers)
        enr = set(keylines(enrolled))
        if not rel:
            v.append("R10: release-tag-signers.txt enrolls no key (fail-closed)")
        for line in rel:
            if line not in enr:
                v.append(f"R10: release signer not enrolled as a commit signer: `{line[:60]}...`")
    return v


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workflow", required=True)
    ap.add_argument("--republish")
    ap.add_argument("--signers")
    ap.add_argument("--enrolled")
    args = ap.parse_args()
    violations = check(args.workflow, args.republish, args.signers, args.enrolled)
    for line in violations:
        print(f"VIOLATION {line}")
    if violations:
        print(f"check-release-workflow: FAIL — {len(violations)} violation(s) in {args.workflow}", file=sys.stderr)
        return 1
    print(f"check-release-workflow: OK — {args.workflow} satisfies R1-R10")
    return 0


if __name__ == "__main__":
    sys.exit(main())
