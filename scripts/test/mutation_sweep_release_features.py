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

def _job(*lines):
    """A one-step workflow whose `run:` is the given lines."""
    return "jobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n" + "".join("          " + x + "\n" for x in lines)


def _env_job(env_lines):
    return ("jobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: cargo build --locked\n        env:\n"
            + env_lines)


_FETCH = "curl -fsSL -o f https://x.example/f"
_CHECK = 'echo "' + "ab" * 32 + '  f" | sha256sum -c -'

# Round 10 (code r9 F1): name -> workflow text that the unmutated guard REFUSES. A mutant that makes the guard accept one
# of these is killed by it even when `--self-test` stays green; the sweep prints the name as the killer.
OBSERVATIONS = {
    "env RUSTFLAGS key with no value": _env_job("          RUSTFLAGS:\n"),
    "env RUSTFLAGS block scalar folding to empty": _env_job("          RUSTFLAGS: >-\n\n"),
    "checksum && then a consumer on the next line": _job(_FETCH, _CHECK + " &&", "tar xzf f"),
    "checksum && then a comment then a consumer": _job(_FETCH, _CHECK + " && # c", "tar xzf f"),
    "checksum && then a consumer in a command substitution": _job(_FETCH, _CHECK + " && x=$(tar xzf f)"),
    "digest text with a command substitution": _job(_FETCH, 'echo "$(true) f" | sha256sum -c -', "tar xzf f"),
    "digest text with backticks": _job(_FETCH, 'echo "`true` f" | sha256sum -c -', "tar xzf f"),
    "function env then env -i": _job("env() { :; }", "env -i cargo build --locked"),
    "function env then env -": _job("env() { :; }", "env - cargo build --locked"),
    "function env then env --ignore-environment": _job("env() { :; }", "env --ignore-environment cargo build --locked"),
}

# Round 10 (code r9 F1): the shapes the reviewer named that are NOT observable. name -> (workflow text, errors at head);
# the unmutated guard and the "unreadable RUSTFLAGS value allowed" mutant give the same count for each, so none of them
# can kill the mutant.
UNOBSERVABLE = {
    "env RUSTFLAGS empty string": (_env_job("          RUSTFLAGS: ''\n"), 0),
    "env RUSTFLAGS tilde": (_env_job("          RUSTFLAGS: ~\n"), 0),
    "env RUSTFLAGS flow sequence": (_env_job("          RUSTFLAGS: [a, b]\n"), 0),
    "env RUSTFLAGS flow mapping": (_env_job("          RUSTFLAGS: {a: b}\n"), 1),
}


def load_guard_module(path):
    import importlib.util

    spec = importlib.util.spec_from_file_location("check_release_features_obs", str(path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def error_counts(path, tree, docs):
    """{name: error count} of ``docs`` ({name: workflow text}) under the guard module at ``path``."""
    mod = load_guard_module(path)
    tree = Path(tree)
    tree.mkdir(parents=True, exist_ok=True)
    return {name: len(mod.r5_errors(doc, None, tree)) for name, doc in docs.items()}


def accepted_observations(path, tree):
    """Names of the OBSERVATIONS the guard module at ``path`` accepts (the unmutated guard accepts none)."""
    return [n for n, c in error_counts(path, tree, OBSERVATIONS).items() if c == 0]


def mutate(text, old, new):
    """The guard text with ``old`` replaced once above CONDITION_MARKER, or None when the anchor is not found exactly once."""
    cut = text.index("# --- end of condition mutants\n")
    head, tail = text[:cut], text[cut:]
    return (head.replace(old, new, 1) + tail) if head.count(old) == 1 else None


# (description, anchor, replacement): mutants that cannot change behaviour. Round 10 (code r9 F1): a row stays here only
# with the observation attempts that failed to tell it from the guard, named in a comment above it. The four rows of
# Round 9 were each tried against OBSERVATIONS; all four were observable, so they are EXTRA_MUTANTS rows now and the
# table is empty. `decision: prove each equivalent row by an attempted observation over keeping the label because the
# reviewer found one of four labels wrong`.
EQUIVALENT_MUTANTS = ()

# (description, anchor, replacement): mutants the guard's own table does not hold; each must be RED. The four that follow
# survive `--self-test` and are killed by a named OBSERVATIONS workflow (the killer column shows `observation: <name>`).
EXTRA_MUTANTS = (
    (
        "literal matrix value not scanned",
        "for label, variant in matrix_variants(raw, ctx):",
        "for label, variant in []:",
    ),
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
    (
        "env -i allowed",
        'if word == "env" and any(a in ("-i", "--ignore-environment", "-") for a in texts):',
        "if False:",
    ),
    (
        "unreadable RUSTFLAGS value allowed",
        "(value is None or RUSTFLAGS_BAD_RE.search(value) is not None)",
        "(value is not None and RUSTFLAGS_BAD_RE.search(value) is not None)",
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


def observe(path, tmpdir):
    """Round 10: the names of the OBSERVATIONS the mutant at ``path`` accepts (run in its own interpreter)."""
    res = subprocess.run([sys.executable, "-I", str(Path(__file__).resolve()), "--observe", str(path), str(Path(tmpdir) / "obs")],
                         capture_output=True, text=True, env=dict(os.environ, TMPDIR=str(tmpdir)))
    if res.returncode != 0:
        return ["observation run failed: " + (res.stderr.strip().splitlines() or ["no output"])[-1][:100]]
    return [ln for ln in res.stdout.splitlines() if ln]


def work(item):
    k, label, mutated, root, tmpdir, equivalent = item
    if mutated is None:
        return k, "OTHER-DEFECT", label
    path = Path(tmpdir) / f"mutant_{k}.py"
    path.write_bytes(mutated)
    rc, _out, err = run_guard(path, root, tmpdir)
    state, note = classify(rc, err, equivalent)
    if rc == 0:  # self-test stayed green: try to tell the mutant from the guard by an observation
        seen = observe(path, tmpdir)
        if seen:
            state, note = "RED", "observation: " + seen[0]
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
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ["--observe"]:  # internal: print the OBSERVATIONS the guard module at argv[1] accepts
        for name in accepted_observations(argv[1], argv[2]):
            print(name)
        return 0
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
