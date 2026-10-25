#!/usr/bin/env python3
"""Parallel mutation sweep for scripts/check_release_features.py (issue 6062).

Port of the guard's own ``--mutation-sweep`` to a multiprocessing pool with one
result line per mutant:

    <id> RED|SURVIVES|EQUIVALENT|OTHER-DEFECT <killer test name | note>

Row 0 is the control: the unmutated guard must be GREEN. Rows 1.. are every
refusal call neutralised in turn (``x.bad(...)``) and every CONDITION_MUTANTS
entry. A mutant is RED when ``--self-test`` fails with a named case
(``self-test FAIL: '<name>'`` on stderr); the first named case is the killer.
A mutant that crashes the guard with a traceback is RED too (killer "crash: <error>").
A mutant that fails without naming a case or a traceback, or whose anchor is not found exactly
once, is an OTHER-DEFECT. A survivor is SURVIVES unless it is listed in
EQUIVALENT_MUTANTS below, where it prints EQUIVALENT (and is RED if killed).

Equivalent mutants live here, not in CONDITION_MUTANTS, because the guard's own
sweep treats every survivor as a failure.

Usage: mutation_sweep_release_features.py [--jobs N] [--root DIR] [--out FILE] [--limit N]
Exit 0 when the control is green and SURVIVES = 0 and OTHER-DEFECTS = 0.
"""
import argparse
import multiprocessing
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
GUARD = HERE.parent / "check_release_features.py"
sys.path.insert(0, str(GUARD.parent))

# (description, anchor, replacement): mutants that cannot change behaviour.
EQUIVALENT_MUTANTS = (
    (
        "chain chain needs the &&",
        'chained = chain is not None and chain[0] == k - 1 and info["prev"] == "&&"',
        "chained = chain is not None and chain[0] == k - 1",
    ),
    (
        "substitution in the checklist allowed",
        'if not alit and ("$(" in arg or "`" in arg):',
        "if False:",
    ),
    # `env` is not on RUN_ALLOWED, so `env -i` is refused as an unlisted command before this defence-in-depth line runs.
    (
        "env -i allowed",
        'if word == "env" and any(a in ("-i", "--ignore-environment", "-") for a in texts):',
        "if False:",
    ),
    # Every caller passes a string value; None only comes from the default argument, so the unreadable-value arm is
    # reachable only by a future caller (the fail-closed default is kept on purpose).
    (
        "unreadable RUSTFLAGS value allowed",
        '(value is None or RUSTFLAGS_BAD_RE.search(value) is not None)',
        '(value is not None and RUSTFLAGS_BAD_RE.search(value) is not None)',
    ),
)

# (description, anchor, replacement): mutants the guard's own table does not hold; each must be RED.
EXTRA_MUTANTS = (
    (
        "literal matrix value not scanned",
        "for label, variant in matrix_variants(raw, ctx):",
        "for label, variant in []:",
    ),
)

FAIL_RE = re.compile(r"self-test FAIL:[^'\n]*'([^']*)'")


def run_guard(path, root, tmpdir):
    env = dict(os.environ)
    env["TMPDIR"] = tmpdir
    res = subprocess.run(
        [sys.executable, "-I", str(path), "--self-test", str(root)],
        capture_output=True, text=True, env=env,
    )
    return res.returncode, res.stdout, res.stderr


def classify(rc, err, equivalent):
    """Return (state, note) for one mutant run."""
    if rc == 0:
        return ("EQUIVALENT" if equivalent else "SURVIVES"), "-"
    m = FAIL_RE.search(err)
    if m:
        return "RED", m.group(1)
    m = re.search(r"self-test FAIL: ([^\n]{1,80})", err)
    if m:  # a named check that is not a table case (for example a helper of the guard)
        return "RED", m.group(1)
    if "Traceback (most recent call last)" in err:  # the mutant made the guard crash: detected, killed by a crash
        return "RED", "crash: " + err.strip().splitlines()[-1][:100]
    return "OTHER-DEFECT", "failed without a named case: " + err.strip().splitlines()[-1][:100] if err.strip() else "failed without output"


def work(item):
    k, label, mutated, root, tmpdir, equivalent = item
    if mutated is None:
        return k, "OTHER-DEFECT", label
    path = Path(tmpdir) / f"mutant_{k}.py"
    path.write_bytes(mutated)
    rc, _out, err = run_guard(path, root, tmpdir)
    state, note = classify(rc, err, equivalent)
    try:
        path.unlink()
    except OSError:
        pass
    return k, state, f"{label} | {note}"


def build_items(root, tmpdir, limit):
    import check_release_features as G

    src = GUARD.read_bytes()
    text = src.decode("utf-8")
    cut = text.index(G.CONDITION_MARKER + "\n")
    head, tail = text[:cut], text[cut:]
    items = []
    k = 1
    for line, start, end in G._refusal_sites(src):
        mutated = src[:start] + b"(lambda *_a, **_k: None)" + src[end:]
        items.append((k, f"refusal call at line {line}", mutated, root, tmpdir, False))
        k += 1
    for desc, old, new in G.CONDITION_MUTANTS:
        n = head.count(old)
        mutated = (head.replace(old, new, 1) + tail).encode("utf-8") if n == 1 else None
        label = desc if n == 1 else f"{desc} (anchor found {n} times, not once)"
        items.append((k, label, mutated, root, tmpdir, False))
        k += 1
    for desc, old, new in EXTRA_MUTANTS:
        n = head.count(old)
        mutated = (head.replace(old, new, 1) + tail).encode("utf-8") if n == 1 else None
        label = desc if n == 1 else f"{desc} (anchor found {n} times, not once)"
        items.append((k, label, mutated, root, tmpdir, False))
        k += 1
    for desc, old, new in EQUIVALENT_MUTANTS:
        n = head.count(old)
        mutated = (head.replace(old, new, 1) + tail).encode("utf-8") if n == 1 else None
        label = desc if n == 1 else f"{desc} (anchor found {n} times, not once)"
        items.append((k, label, mutated, root, tmpdir, True))
        k += 1
    return items[:limit] if limit else items


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--jobs", type=int, default=max(1, (os.cpu_count() or 2) // 2))
    ap.add_argument("--root", default=str(HERE.parent.parent))
    ap.add_argument("--out", default="")
    ap.add_argument("--limit", type=int, default=0, help="run only the first N mutants (debug)")
    args = ap.parse_args(argv)
    root = Path(args.root).resolve()
    base = root / ".local-runs"
    base.mkdir(parents=True, exist_ok=True)
    started = time.time()
    lines = []
    with tempfile.TemporaryDirectory(prefix="relfeat-par.", dir=str(base)) as tmpdir:
        rc, _o, err = run_guard(GUARD, root, tmpdir)
        control = "GREEN" if rc == 0 else "RED"
        lines.append(f"0 CONTROL-{control} unmutated guard")
        counts = {"RED": 0, "EQUIVALENT": 0, "SURVIVES": 0, "OTHER-DEFECT": 0}
        if rc == 0:
            items = build_items(root, tmpdir, args.limit)
            with multiprocessing.Pool(max(1, args.jobs)) as pool:
                for k, state, note in pool.imap_unordered(work, items):
                    counts[state] += 1
                    lines.append(f"{k} {state} {note}")
        else:
            lines.append(err.strip()[-300:])
    lines[1:] = sorted(lines[1:], key=lambda s: int(s.split(" ", 1)[0]) if s.split(" ", 1)[0].isdigit() else 0)
    total = sum(counts.values())
    summary = (f"RED {counts['RED']} / EQUIVALENT {counts['EQUIVALENT']} / SURVIVES {counts['SURVIVES']} / "
               f"OTHER-DEFECTS {counts['OTHER-DEFECT']} (rows run: {total + 1})")
    wall = f"wall time {time.time() - started:.0f} s with {args.jobs} jobs"
    lines += [summary, wall]
    text = "\n".join(lines) + "\n"
    sys.stdout.write(text)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    ok = rc == 0 and counts["SURVIVES"] == 0 and counts["OTHER-DEFECT"] == 0
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
