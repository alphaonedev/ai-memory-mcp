#!/usr/bin/env python3
"""Assert the #3607 enterprise-federation posture LADDER (#5036), fail-closed.

Why this exists
---------------
`scripts/recapture-cert-3607-posture.sh` wraps each of its four doctor legs in
`set +e ... e_n=$?  ... set -e` and writes `e1..e4` into
`evidence/posture-legs-exit-codes.txt`. Before #5036 it never compared any leg
to an expected value, so the four-leg ladder was a TRANSCRIPT, not a GATE: if a
regression bypassed posture enforcement so that leg 1 (bare env, zero controls)
began exiting 0 with 22 PASS, the script recorded `exit: 0` and still exited 0.
A check that cannot fail measures nothing (#3899 able-to-fail condition).

The recapture script now invokes this gate as its last step and exits with its
status. It is the same fail-closed, self-testing shape as
`scripts/check-cert-leg-nonvacuity.sh` (#3552). The expected ladder is pinned
by the #3003 / #3553 doctor exit-code contract, quoted verbatim in the leg-3
refusal capture itself: the diagnostic "bypasses this boot gate (#3003) so it
renders the full report even while the gate is armed, and exits 0 once every
control passes (2 while any fails)".

  leg 1  bare (env -i, NO_CONFIG only)          exit 2   diagnostic: controls fail
  leg 2  hardened, non-sqlcipher, gate NOT armed exit 2   ENCRYPT_AT_REST needs sqlcipher
  leg 3  hardened, non-sqlcipher, gate ARMED     exit 1   boot gate REFUSES
  leg 4  sqlcipher + encrypt + gate ARMED        exit 0   every control passes

It also asserts the monotone PASS/FAIL shape across the legs and that the
leg-3 refusal capture is non-empty and names the control it refused on -- an
empty refusal file would otherwise satisfy a mere existence check.

Exit codes: 0 = ladder asserted green, 1 = ladder VIOLATED, 2 = usage/missing
evidence. `--self-test` runs the planted negative controls and exits 0 only if
every mutant is correctly REJECTED.

Usage:
  check-posture-ladder.py EVIDENCE_DIR [--default-bin P --sqlcipher-bin P]
  check-posture-ladder.py EVIDENCE_DIR --self-test
"""

import argparse
import hashlib
import os
import pathlib
import re
import shutil
import sys

# (label, expected shell exit) -- the #3003/#3553 contract.
EXPECTED_LADDER = (
    ("leg 1", 2),
    ("leg 2", 2),
    ("leg 3", 1),
    ("leg 4", 0),
)

# Expected [PASS]/[FAIL] shape per capture. None = not asserted (the refusal
# capture carries prose, not check lines).
EXPECTED_COUNTS = {
    "posture-bare-env.out": (12, 10),
    "posture-hardened-env.out": (20, 2),
    "posture-sqlcipher-pass.out": (22, 0),
}

LEG_RE = re.compile(r"^##\s*(leg\s*\d+)\b", re.I)
EXIT_RE = re.compile(r"^exit:\s*(\S+)\s*$", re.I)


def parse_ladder(transcript):
    """Return [(leg_label, exit_token)] in file order from the transcript."""
    legs = []
    pending = None
    for line in transcript.read_text(errors="replace").splitlines():
        m = LEG_RE.match(line.strip())
        if m:
            pending = " ".join(m.group(1).lower().split())
            continue
        m = EXIT_RE.match(line.strip())
        if m and pending is not None:
            legs.append((pending, m.group(1)))
            pending = None
    return legs


def check(evdir, out, bins=None):
    """Assert the ladder. Returns a list of violation strings (empty == green)."""
    bad = []
    transcript = evdir / "posture-legs-exit-codes.txt"
    if not transcript.is_file():
        return ["posture-legs-exit-codes.txt MISSING"]

    legs = parse_ladder(transcript)
    if len(legs) != len(EXPECTED_LADDER):
        bad.append(
            "ladder has %d legs, expected %d" % (len(legs), len(EXPECTED_LADDER))
        )

    for idx, (want_label, want_exit) in enumerate(EXPECTED_LADDER):
        if idx >= len(legs):
            bad.append("%s: MISSING from transcript" % want_label)
            continue
        got_label, got_exit = legs[idx]
        if not got_label.startswith(want_label):
            bad.append(
                "position %d: expected %s, transcript says %r"
                % (idx + 1, want_label, got_label)
            )
        if got_exit != str(want_exit):
            bad.append(
                "%s: exit %s, EXPECTED %d -- posture enforcement shape changed"
                % (want_label, got_exit, want_exit)
            )
        else:
            out.append("  %s exit=%s  OK" % (want_label, got_exit))

    for name, (want_pass, want_fail) in sorted(EXPECTED_COUNTS.items()):
        f = evdir / name
        if not f.is_file():
            bad.append("%s MISSING" % name)
            continue
        text = f.read_text(errors="replace")
        got = (text.count("[PASS]"), text.count("[FAIL]"))
        if got != (want_pass, want_fail):
            bad.append(
                "%s PASS=%d FAIL=%d, EXPECTED PASS=%d FAIL=%d"
                % (name, got[0], got[1], want_pass, want_fail)
            )
        else:
            out.append("  %s PASS=%d FAIL=%d  OK" % (name, got[0], got[1]))

    # Monotone: strictly fewer failures as controls are added.
    fails = []
    for name in ("posture-bare-env.out", "posture-hardened-env.out",
                 "posture-sqlcipher-pass.out"):
        f = evdir / name
        if f.is_file():
            fails.append(f.read_text(errors="replace").count("[FAIL]"))
    if len(fails) == 3 and not (fails[0] > fails[1] > fails[2] == 0):
        bad.append(
            "FAIL counts %r are not strictly decreasing to 0 -- the ladder "
            "does not demonstrate controls taking effect" % (fails,)
        )
    elif len(fails) == 3:
        out.append("  monotone FAIL %d > %d > %d == 0  OK" % tuple(fails))

    # Leg 4's exit 0 is only meaningful if it came from a genuine sqlcipher
    # build: the same transcript shape from a NON-sqlcipher binary would be a
    # false green (#4830 saw 2/2/1/2 on a host whose binary lacked the
    # feature). When the recapture passes both binaries, their digests must
    # differ.
    if bins is not None:
        digests = []
        for b in bins:
            try:
                digests.append(hashlib.sha256(pathlib.Path(b).read_bytes()).hexdigest())
            except OSError as exc:
                bad.append("cannot read binary %s for digest: %s" % (b, exc))
        if len(digests) == 2:
            if digests[0] == digests[1]:
                bad.append(
                    "default and sqlcipher binaries share sha256 %s -- leg 4 "
                    "exit 0 was NOT produced by a distinct sqlcipher build"
                    % digests[0]
                )
            else:
                out.append("  leg 4 backed by distinct sqlcipher build %s != %s  OK"
                           % (digests[0][:12], digests[1][:12]))

    # The leg-3 refusal must be a real refusal, not an empty file.
    refusal = evdir / "posture-hardened-boot-refusal.out"
    if not refusal.is_file():
        bad.append("posture-hardened-boot-refusal.out MISSING")
    else:
        text = refusal.read_text(errors="replace")
        if "refuses to boot" not in text:
            bad.append("refusal capture does not contain 'refuses to boot'")
        elif not re.search(r"required control\(s\) missing or below floor", text):
            bad.append("refusal capture names no missing control")
        else:
            named = re.findall(r"^\s+-\s+(AI_MEMORY_\w+):", text, re.M)
            if not named:
                bad.append("refusal capture lists no AI_MEMORY_* control")
            else:
                out.append("  leg 3 refusal names %s  OK" % ",".join(named))

    return bad


MUTANTS = (
    ("leg1 passes (posture bypassed)", "posture-legs-exit-codes.txt",
     lambda t: t.replace("## leg 1: bare (env -i, AI_MEMORY_NO_CONFIG=1 only)\nexit: 2",
                         "## leg 1: bare (env -i, AI_MEMORY_NO_CONFIG=1 only)\nexit: 0")),
    ("leg4 regressed to fail", "posture-legs-exit-codes.txt",
     lambda t: t.replace("## leg 4: sqlcipher build, ENCRYPT_AT_REST=1, boot gate ARMED\nexit: 0",
                         "## leg 4: sqlcipher build, ENCRYPT_AT_REST=1, boot gate ARMED\nexit: 2")),
    ("leg3 boot gate stopped refusing", "posture-legs-exit-codes.txt",
     lambda t: t.replace("boot gate ARMED (AI_MEMORY_REQUIRE_ENTERPRISE_FEDERATION_POSTURE=1)\nexit: 1",
                         "boot gate ARMED (AI_MEMORY_REQUIRE_ENTERPRISE_FEDERATION_POSTURE=1)\nexit: 0")),
    ("bare env silently all-pass", "posture-bare-env.out",
     lambda t: t.replace("[FAIL]", "[PASS]")),
    ("sqlcipher leg lost a check", "posture-sqlcipher-pass.out",
     lambda t: t.replace("[PASS]", "", 1)),
    ("refusal capture emptied", "posture-hardened-boot-refusal.out",
     lambda t: ""),
)


def self_test(evdir):
    """Plant each mutant on a COPY and require the gate to REJECT it."""
    live_out = []
    live_bad = check(evdir, live_out)
    print("baseline (unmutated live evidence): %s"
          % ("GREEN" if not live_bad else "RED %r" % live_bad))
    if live_bad:
        print("SELF-TEST ABORT: baseline is not green, cannot calibrate", file=sys.stderr)
        return 2

    failures = 0
    for idx, (label, target, mutate) in enumerate(MUTANTS):
        tmp = pathlib.Path(evdir.parent) / ("ladder-selftest-%d-%d" % (os.getpid(), idx))
        tmp.mkdir()
        try:
            dst = tmp / "evidence"
            shutil.copytree(str(evdir), str(dst))
            f = dst / target
            if not f.is_file():
                print("  MUTANT %-38s SKIP (no %s)" % (label, target))
                continue
            before = f.read_text(errors="replace")
            after = mutate(before)
            if after == before:
                print("  MUTANT %-38s NOT PLANTED (no-op edit)" % label)
                failures += 1
                continue
            f.write_text(after)
            bad = check(dst, [])
            if bad:
                print("  MUTANT %-38s REJECTED  <- %s" % (label, bad[0]))
            else:
                print("  MUTANT %-38s *** ACCEPTED -- GATE IS BLIND ***" % label)
                failures += 1
        finally:
            shutil.rmtree(str(tmp), ignore_errors=True)

    print("self-test: %d/%d mutants rejected" % (len(MUTANTS) - failures, len(MUTANTS)))
    return 0 if failures == 0 else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("evidence", type=pathlib.Path,
                    help="the run's evidence/ directory")
    ap.add_argument("--default-bin", type=pathlib.Path,
                    help="default-build binary (digest must differ from --sqlcipher-bin)")
    ap.add_argument("--sqlcipher-bin", type=pathlib.Path,
                    help="sqlcipher-build binary used for leg 4")
    ap.add_argument("--self-test", action="store_true",
                    help="plant negative controls on copies; prove the gate can fail")
    args = ap.parse_args()

    evdir = args.evidence
    if not evdir.is_dir():
        print("no such evidence dir: %s" % evdir, file=sys.stderr)
        return 2

    if args.self_test:
        return self_test(evdir)

    if bool(args.default_bin) != bool(args.sqlcipher_bin):
        print("--default-bin and --sqlcipher-bin must be given together", file=sys.stderr)
        return 2
    bins = (args.default_bin, args.sqlcipher_bin) if args.default_bin else None
    out = []
    bad = check(evdir, out, bins)
    print("POSTURE LADDER GATE  evidence=%s" % evdir)
    for line in out:
        print(line)
    if bad:
        print("LADDER VIOLATED (%d):" % len(bad))
        for b in bad:
            print("  !! %s" % b)
        return 1
    print("LADDER ASSERTED GREEN (%d legs, #3003/#3553 contract)" % len(EXPECTED_LADDER))
    return 0


if __name__ == "__main__":
    sys.exit(main())
