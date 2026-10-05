#!/usr/bin/env python3
"""Inject each credential spelling into a scratch copy of a tree and run the three real CLIs.

For every spelling in CRED_SPELLINGS (read from a copy of the gate, by default the one beside
this script) the line is added to infra/aws-gpu-burst/cloud-init-memory.yaml.tpl in a COPY of
the tree, then the gate scan (stderr), --list-triggers (stdout) and the regen report (stdout
and stderr; never --accept-new) are run, and each output is searched for the synthetic secret.
The tree is never changed: pass a directory made with git archive.

Usage: cloud-init-redaction-probe.py <tree-copy> [--spellings-from <gate.py>] [--only F1,F3]
Exit 0 when no output holds a byte of the secret, 1 otherwise (#5546-#5550).
"""
import argparse
import importlib.util
import subprocess
import sys
from pathlib import Path

ANCHOR = 'echo "=== ai-memory postgres+AGE+pgvector provision'
TEMPLATE = "infra/aws-gpu-burst/cloud-init-memory.yaml.tpl"
CHANNELS = (
    ("scan", ["scripts/check-cloud-init-serve-flags.py"]),
    ("list", ["scripts/check-cloud-init-serve-flags.py", "--list-triggers"]),
    ("regen", ["scripts/regen-cloud-init-token-allow.py", "."]),
)


def load_gate(path: Path):
    spec = importlib.util.spec_from_file_location("gate_for_spellings", str(path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("tree", help="a copy of the repository (git archive), changed in place and restored")
    ap.add_argument("--spellings-from", default=str(Path(__file__).with_name("check-cloud-init-serve-flags.py")))
    ap.add_argument("--only", default="", help="comma list of finding classes, e.g. F1,F3")
    a = ap.parse_args()
    gate = load_gate(Path(a.spellings_from))
    tree = Path(a.tree)
    tpl = tree / TEMPLATE
    orig = tpl.read_text(encoding="utf-8")
    lines = orig.split("\n")
    k = next(i for i, ln in enumerate(lines) if ANCHOR in ln)
    leaks = 0
    try:
        for cls, label, text in gate.CRED_SPELLINGS:
            if a.only and cls not in a.only.split(","):
                continue
            body = ["      " + x for x in text.split("\n")]
            tpl.write_text("\n".join(lines[:k + 1] + body + lines[k + 1:]), encoding="utf-8", newline="")
            res = {}
            for name, cmd in CHANNELS:
                p = subprocess.run([sys.executable] + cmd, cwd=str(tree), capture_output=True, text=True)
                out = p.stdout + p.stderr
                res[name] = "ok"
                if any(n in out for n in gate.CRED_NEEDLES):
                    res[name] = "LEAK"
                elif "Traceback" in out:
                    res[name] = "TRACEBACK"
            leaks += sum(v != "ok" for v in res.values())
            print("%s %-34s scan=%-9s list=%-9s regen=%-9s" % (cls, label, res["scan"], res["list"], res["regen"]), flush=True)
    finally:
        tpl.write_text(orig, encoding="utf-8", newline="")
    print("leaking or failing channels: %d" % leaks)
    return 1 if leaks else 0


if __name__ == "__main__":
    sys.exit(main())
