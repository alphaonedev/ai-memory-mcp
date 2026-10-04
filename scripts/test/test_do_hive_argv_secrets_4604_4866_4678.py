#!/usr/bin/env python3
"""Round-4 regression probes for PR 4671 (#4604 F4, #4866 F5, #4678 F6).

Each probe extracts the shipped text (template or script), runs it under bash
with a stand-in for curl or sed that records its argv and its stdin, and
asserts the secret is on no argv and still reaches the program on stdin. The
F6 probe feeds mixed-case releases/latest URLs to spawn.sh require_image_pin.
Standard library only; exits 1 on any failed probe.
"""
import os
import pathlib
import re
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
TPL = ROOT / "infra/do-hive/cloud-init-memory.yaml.tpl"
FED = ROOT / "infra/do-hive/federate.sh"
SPAWN = ROOT / "infra/do-hive/spawn.sh"
# 64 lowercase hex: the shape the sites now require before building a curl config line.
SECRET = "5ec4e7" + "0123456789abcdef" * 3 + "a1b2c3d4e5"
FAILS = []


def probe(name, ok, detail=""):
    print("%s: %s %s" % ("ok" if ok else "FAIL", name, detail))
    if not ok:
        FAILS.append(name)


def section(text, start, end):
    i = text.index(start)
    return text[i:text.index(end, i)]


def stub_dir(d, name, real=None):
    """A PATH stand-in: logs argv (one arg per line) and stdin, then runs real if given."""
    p = d / name
    body = ['#!/bin/bash', 'printf "%s\\n" "$@" > "$LOGDIR/NAME.argv"',
            'cat > "$LOGDIR/NAME.stdin"' if not real else 'tee "$LOGDIR/NAME.stdin" | REAL "$@"']
    if not real:
        body.append('exit 0')
    body = [x.replace("NAME", name).replace("REAL", real or "") for x in body]
    p.write_text("\n".join(body) + "\n")
    p.chmod(0o755)


def run_bash(script, d, extra_env=None):
    env = dict(os.environ, PATH=str(d) + os.pathsep + os.environ["PATH"], LOGDIR=str(d))
    env.update(extra_env or {})
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env)


def assert_off_argv(name, d, prog, want_in_stdin):
    argv = (d / (prog + ".argv")).read_text() if (d / (prog + ".argv")).exists() else ""
    stdin = (d / (prog + ".stdin")).read_text() if (d / (prog + ".stdin")).exists() else ""
    probe(name + ": secret not on argv", SECRET not in argv)
    probe(name + ": secret reaches %s on stdin" % prog, want_in_stdin in stdin, repr(stdin[:60]))


def f4_sed():
    tpl = TPL.read_text()
    m = re.search(r"^[ ]*# The script reaches sed on stdin.*?^[ ]*unset NEW_SECRET\n", tpl, re.S | re.M)
    probe("F4 sed mint block present", bool(m))
    if not m:
        return
    with tempfile.TemporaryDirectory(dir=str(ROOT / ".local-runs")) as t:
        d = pathlib.Path(t)
        stub_dir(d, "sed", real="/usr/bin/sed")
        f = d / "store-url"
        f.write_text("postgres://aimemory:CHANGEME@localhost/aimemory\n")
        block = m.group(0).replace("/etc/ai-memory/store-url", str(f))
        r = run_bash("NEW_SECRET=%s\n%s" % (SECRET, block), d)
        probe("F4 sed rc 0", r.returncode == 0, r.stderr[:80])
        probe("F4 store-url holds the minted value", SECRET in f.read_text() and "CHANGEME" not in f.read_text())
        assert_off_argv("F4 sed", d, "sed", SECRET)


def f5_admin_call():
    tpl = TPL.read_text()
    fn = section(tpl, "admin_call() {", "\n      }\n") + "\n      }\n"
    fn = fn.replace("%%{", "%{")
    with tempfile.TemporaryDirectory(dir=str(ROOT / ".local-runs")) as t:
        d = pathlib.Path(t)
        stub_dir(d, "curl")
        script = 'FED_DIR=/x ADMIN_ID=a API_KEY=%s\n%s\nadmin_call -X POST http://127.0.0.1/\n' % (SECRET, fn)
        r = run_bash(script, d)
        probe("F5 admin_call rc 0", r.returncode == 0, r.stderr[:80])
        assert_off_argv("F5 admin_call", d, "curl", "x-api-key: " + SECRET)


def f5_federate():
    fs = FED.read_text()
    for fname, arg in (("node_get", "1 mem-1"), ("node_post", "1 e30=")):
        fn = section(fs, fname + "() {", "\n}\n") + "\n}\n"
        with tempfile.TemporaryDirectory(dir=str(ROOT / ".local-runs")) as t:
            d = pathlib.Path(t)
            stub_dir(d, "curl")
            key = d / "api-key"
            key.write_text(SECRET + "\n")
            script = ("AUTHOR_ID=au\nnode_sh() { /usr/bin/sed 's#/etc/ai-memory/api-key#%s#' | bash; }\n%s\n%s %s\n"
                      % (key, fn, fname, arg))
            r = run_bash(script, d)
            probe("F5 %s rc 0" % fname, r.returncode == 0, r.stderr[:80])
            assert_off_argv("F5 " + fname, d, "curl", "x-api-key: " + SECRET)
    line = next(l for l in fs.splitlines() if l.lstrip().startswith("lg_curl()"))
    with tempfile.TemporaryDirectory(dir=str(ROOT / ".local-runs")) as t:
        d = pathlib.Path(t)
        stub_dir(d, "curl")
        r = run_bash('OUT_DIR=/o api_key=%s\n%s\nlg_curl http://127.0.0.1/\n' % (SECRET, line), d)
        probe("F5 lg_curl rc 0", r.returncode == 0, r.stderr[:80])
        assert_off_argv("F5 lg_curl", d, "curl", "X-API-Key: " + SECRET)


def f6_spawn():
    fn = section(SPAWN.read_text(), "require_image_pin() {", "\ncase ")
    sha = "a" * 64
    cases = [("https://h/o/v1/a.tgz", True), ("https://h/releases/latest/x", False),
             ("https://h/RELEASES/LATEST/x", False), ("https://h/rElEaSeS/lAtEsT/x", False),
             ("https://h/Releases/latest/x", False), ("https://h/releases/LATEST/x", False)]
    with tempfile.TemporaryDirectory(dir=str(ROOT / ".local-runs")) as t:
        script = pathlib.Path(t) / "fn.sh"
        script.write_text(fn + "\nrequire_image_pin\necho PASSED\n")
        for url, want in cases:
            env = dict(os.environ, TF_VAR_ai_memory_image_url=url, TF_VAR_ai_memory_image_sha256=sha)
            r = subprocess.run(["bash", str(script)], capture_output=True, text=True, env=env)
            probe("F6 spawn url=%s accepted=%s" % (url, want), ("PASSED" in r.stdout) == want, "rc=%d" % r.returncode)


def main():
    (ROOT / ".local-runs").mkdir(exist_ok=True)
    f4_sed()
    f5_admin_call()
    f5_federate()
    f6_spawn()
    print("RESULT: %s (%d failed)" % ("FAIL" if FAILS else "PASS", len(FAILS)))
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
