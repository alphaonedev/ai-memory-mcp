#!/usr/bin/env python3
"""Mutation run for the cloud-init redaction code (#5551; PR #4655 round 16).

Each mutant is one text substitution in scripts/check-cloud-init-serve-flags.py or
scripts/regen-cloud-init-token-allow.py, applied to a copy of scripts/, infra/ and src/daemon_runtime.rs taken from a
git revision. A mutant is killed when the gate self-test, the regen self-test, or the gate
scan or the regen run on the copy exits non-zero. The unmutated control runs before and after
and must be green. At most 2 copies run at once (each self-test takes about 2.5 minutes).
A mutant whose substitution does not match exactly once is reported as INVALID, never as killed.

Usage: cloud-init-gate-mutants.py [--rev HEAD] [--workdir DIR] [--only ID,ID] [--jobs 2]
Exit 0 when the controls are green and every mutant is killed.
"""
import argparse
import concurrent.futures
import shutil
import subprocess
import sys
import tarfile
import io
from pathlib import Path

G = "scripts/check-cloud-init-serve-flags.py"
R = "scripts/regen-cloud-init-token-allow.py"

# the spelling, layer and funnel pins alone (seconds), before the 2.5 minute gate self-test
PINS = (
    "import importlib.util, sys\n"
    "s = importlib.util.spec_from_file_location('g', 'scripts/check-cloud-init-serve-flags.py')\n"
    "g = importlib.util.module_from_spec(s); s.loader.exec_module(g)\n"
    "bad = g.spelling_problems(g.load_repo()) + g.print_funnel_problems((g.__file__, 'scripts/regen-cloud-init-token-allow.py'))\n"
    "sys.exit(1 if bad else 0)\n"
)

# (id, file, old text, new text, why it matters)
MUTANTS = (
    ("M01", G, "masked = mask_keyword_values(mask_credentials(text))", "masked = mask_credentials(text)", "scrub skips the keyword over-approximation"),
    ("M02", G, "(?=[\\s;&|)⏎\\\\]|$)\" % (CRED_PLACEHOLDER", "\" % (CRED_PLACEHOLDER", "placeholder exemption loses its word boundary"),
    ("M03", G, 'CRED_LINE_RE = re.compile(r"(?:\\\\\\n|[^\\n])*")', 'CRED_LINE_RE = re.compile(r"[^\\n]*")', "mask stops at a backslash continuation"),
    ("M04", G, 'CRED_FREE_RE = re.compile(r"CHANGEME|', 'CRED_FREE_RE = re.compile(r"(?:var|local|module|data)\\.[\\w.\\[\\]-]+|CHANGEME|', "terraform-looking value is exempt again (F5)"),
    ("M05", G, "        elif c in \"'\\\"\" or (c == \"$\" and text[j + 1:j + 2] == \"'\"):", "        elif c == \"$\" and text[j + 1:j + 2] == \"'\":", "a quote does not join the shell word (F1)"),
    ("M06", G, "return [m.group(1), re.sub(r\"\\\\(.)\", r\"\\1\", m.group(1), flags=re.S)]", "return [m.group(1)]", "libpq value not unescaped (F2)"),
    ("M07", G, "r\"'((?:\\\\.|[^'\\\\])*)'\"", "r\"'([^']*)'\"", "libpq escaped quote ends the value (F2)"),
    ("M08", G, "for variant in (text, text.replace(\"\\\\\\n\", \"\"), text.replace(\"\\\\\\n\", \"\\\\⏎\")):", "for variant in (text, text.replace(\"\\\\\\n\", \"\\\\⏎\")):", "joined continuation not registered (F3)"),
    ("M09", G, "for variant in (text, text.replace(\"\\\\\\n\", \"\"), text.replace(\"\\\\\\n\", \"\\\\⏎\")):", "for variant in (text, text.replace(\"\\\\\\n\", \"\")):", "displayed continuation not registered (F3)"),
    ("M10", G, "            found.extend(CRED_MIXED_RE.findall(line[m.end():]))\n", "", "line-tail pieces not registered"),
    ("M11", G, "            found.extend(libpq_value(line, m.end()))\n", "", "libpq reader not used"),
    ("M12", G, "            found.extend(read_shell_word(line, m.end()))\n", "", "shell word reader not used"),
    ("M13", G, "print(scrub(text), file=sys.stdout if file is None else file)", "print(text, file=sys.stdout if file is None else file)", "say does not scrub"),
    ("M14", G, "if isinstance(f, ast.Name) and f.id == \"print\":", "if isinstance(f, ast.Name) and f.id == \"prin\":", "funnel check ignores print"),
    ("M15", G, "if isinstance(n, ast.FunctionDef) and n.name == \"say\":", "if isinstance(n, ast.FunctionDef) and n.name != \"say\":", "funnel check exempts every other function"),
    ("M16", R, "out += [\"NEW: %s | %s | %s\" % (k[0], k[1], g.scrub(k[2]))", "out += [\"NEW: %s | %s | %s\" % (k[0], k[1], g.mask_credentials(k[2]))", "regen NEW line not scrubbed"),
    ("M17", R, "out = [\"FAULT: \" + g.scrub(f) for f in faults]", "out = [\"FAULT: \" + f for f in faults]", "regen fault not scrubbed"),
    ("M18", R, "out.append(\"    \" + g.scrub(d))", "out.append(\"    \" + g.mask_credentials(d))", "regen CHANGED diff line not scrubbed"),
    ("M19", R, "g.say(\"\\n\".join(lines))", "print(\"\\n\".join(lines))", "regen report bypasses the funnel"),
    ("M20", G, "r\"(?:[\\w-]*pass(?:word|wd|phrase)\\w*[\\\"']?\\s*[=:]|", "r\"(?:[\\w-]*pass(?:word|wd)\\w*[\\\"']?\\s*[=:]|", "passphrase is not a keyword"),
    ("M21", G, "|\\bpass(?:word|wd)(?=\\s+(?:E|U&)?['\\\"$]))", ")", "SQL PASSWORD literal keyword dropped"),
    ("M22", G, "[\\w-]*pass(?:word|wd|phrase)\\w*[\\\"']?\\s*[=:]|", "[\\w-]*pass(?:word|wd|phrase)\\w*\\s*[=:]|", "JSON quoted key not a keyword"),
    ("M23", G, "if ch == \"@\" and \":\" in rest[:e]:", "if ch == \"@\":", "URL without a password registers its user"),
    ("M24", G, "        out.append(text[i:m.end()])\n        ph = CRED_PLACEHOLDER_RE.match(text, m.end())", "        out.append(text[i:m.end()])\n        ph = None", "no placeholder exemption (masks too much, shown value lost)"),
    ("M25", G, "        end = CRED_LINE_RE.match(text, m.end()).end()\n        if end > m.end():\n            out.append(CRED_MASK)", "        end = CRED_LINE_RE.match(text, m.end()).end()", "keyword tail dropped instead of masked"),
    ("M26", G, "        globals()[\"load_repo\"] = real\n        CRED_PIECES.clear()", "        globals()[\"load_repo\"] = real", "spelling run leaves its pieces registered"),
    ("M27", R, "    g.CRED_PIECES.clear()\n    return bad", "    return bad", "regen spelling loop leaves pieces registered"),
    ("M28", G, "out.append(\"%s | %s | %s\" % (scope_of(nm), ln.ctx, scrub(ln.text)))", "out.append(\"%s | %s | %s\" % (scope_of(nm), ln.ctx, ln.text))", "list_triggers returns unscrubbed text (say() also scrubs)"),
    ("M29", G, "SCRUB_PLACEHOLDER = r\"(?![\\w.-]*:CHANGEME@[^@\\n]*(?:\\n|$))\"", "SCRUB_PLACEHOLDER = r\"\"", "the CHANGEME userinfo is masked too"),
    ("M30", G, "and not (hcl and HCL_REFERENCE_RE.fullmatch(w))", "and not (False and HCL_REFERENCE_RE.fullmatch(w))", "main.tf var.X reference registered as a secret"),
    ("M31", G, "and line[m.end():m.end() + 1] == '\"':", "and False:", "PASSWORD then a double quote registered as a secret"),
)


def snapshot(rev: str, dest: Path) -> None:
    raw = subprocess.run(["git", "archive", rev, "scripts", "infra", "src/daemon_runtime.rs"], check=True, capture_output=True).stdout
    with tarfile.open(fileobj=io.BytesIO(raw)) as tf:
        tf.extractall(str(dest), **({"filter": "data"} if hasattr(tarfile, "data_filter") else {}))


def run(dest: Path, cmd: list) -> int:
    return subprocess.run([sys.executable] + cmd, cwd=str(dest), capture_output=True, text=True).returncode


def kill_check(dest: Path) -> str:
    """The first check that fails, or empty when the copy is green."""
    for name, cmd in (("scan", [G]), ("regen", [R, "."]), ("pins", ["-c", PINS]), ("regen-self-test", [R, "--self-test", "."]), ("gate-self-test", [G, "--self-test"])):
        if run(dest, cmd) != 0:
            return name
    return ""


def one(mid, rel, old, new, why, args, root) -> tuple:
    dest = root / mid
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    snapshot(args.rev, dest)
    path = dest / rel
    text = path.read_text(encoding="utf-8")
    if old and text.count(old) != 1:
        return mid, why, "INVALID (substitution matched %d times)" % text.count(old)
    path.write_text(text.replace(old, new, 1), encoding="utf-8")
    killer = kill_check(dest)
    shutil.rmtree(dest)
    return mid, why, ("killed by " + killer) if killer else "SURVIVED"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--rev", default="HEAD")
    ap.add_argument("--workdir", default=".local-runs/mutants")
    ap.add_argument("--only", default="")
    ap.add_argument("--jobs", type=int, default=2)
    args = ap.parse_args()
    root = Path(args.workdir).resolve()
    root.mkdir(parents=True, exist_ok=True)
    only = set(x for x in args.only.split(",") if x)
    sha = subprocess.run(["git", "rev-parse", args.rev], capture_output=True, text=True).stdout.strip()
    print("revision %s, %d mutants" % (sha, len(MUTANTS)), flush=True)
    controls = {}
    for tag in ("control-before",):
        controls[tag] = one(tag, G, "", "", "unmutated copy", args, root)[2]
        print(tag, "green" if controls[tag] == "SURVIVED" else "RED " + controls[tag], flush=True)
    if controls["control-before"] != "SURVIVED":
        print("the unmutated control is not green, so no mutant result would mean anything")
        return 1
    pool = [m for m in MUTANTS if not only or m[0] in only]
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, min(2, args.jobs))) as ex:
        futs = [ex.submit(one, m[0], m[1], m[2], m[3], m[4], args, root) for m in pool]
        for f in concurrent.futures.as_completed(futs):
            r = f.result()
            results.append(r)
            print("%s | %s | %s" % (r[0], r[2], r[1]), flush=True)
    controls["control-after"] = one("control-after", G, "", "", "unmutated copy", args, root)[2]
    print("control-after", "green" if controls["control-after"] == "SURVIVED" else "RED " + controls["control-after"], flush=True)
    bad = [r for r in results if not r[2].startswith("killed")]
    ok = all(v == "SURVIVED" for v in controls.values())  # no check failed on the unmutated copy
    print("mutants %d, killed %d, not killed %d; controls %s" % (len(results), len(results) - len(bad), len(bad), "green" if ok else "NOT GREEN"))
    return 0 if ok and not bad else 1


if __name__ == "__main__":
    sys.exit(main())
