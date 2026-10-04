#!/usr/bin/env python3
"""Round-4/5 regression probes for PR 4671 (#4604 F4, #4866 F5, #4678 F6, #4898 N1, #4893 P1).

Each probe extracts the shipped text (template or script), runs it under bash
with a stand-in for curl or sed that records its argv and its stdin, and
asserts the secret is on no argv and still reaches the program on stdin. The
F6 probe feeds mixed-case and dot-segment releases/latest URLs to spawn.sh
require_image_pin (N3). The N1 probes feed a hostile api key (valid hex, then a
quote, a newline and a curl option) to every curl-config site and assert no
extra option reaches curl. The P1 probe asserts federate.sh never prints the
node API key and writes it to a 0600 file.
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
             ("https://h/Releases/latest/x", False), ("https://h/releases/LATEST/x", False),
             ("https://h/releases/./latest", False), ("https://h/releases/x/../latest", False),
             ("https://h/releases//latest", False), ("https://h/o/v1/./a.tgz", False)]
    with tempfile.TemporaryDirectory(dir=str(ROOT / ".local-runs")) as t:
        script = pathlib.Path(t) / "fn.sh"
        script.write_text(fn + "\nrequire_image_pin\necho PASSED\n")
        for url, want in cases:
            env = dict(os.environ, TF_VAR_ai_memory_image_url=url, TF_VAR_ai_memory_image_sha256=sha)
            r = subprocess.run(["bash", str(script)], capture_output=True, text=True, env=env)
            probe("F6 spawn url=%s accepted=%s" % (url, want), ("PASSED" in r.stdout) == want, "rc=%d" % r.returncode)


HOSTILE = SECRET + '"\noutput = "marker-n1"\nurl = "http://127.0.0.1:9/"'


def curl_stdin_clean(d):
    p = d / "curl.stdin"
    return (not p.exists()) or ("output =" not in p.read_text() and "url =" not in p.read_text())


def n1_curl_config_injection():
    tpl = TPL.read_text()
    guard = next((l.strip() for l in tpl.splitlines() if l.lstrip().startswith('[[ "$API_KEY" =~')), "")
    probe("N1 template has an API_KEY format guard", bool(guard))
    fn = section(tpl, "admin_call() {", "\n      }\n") + "\n      }\n"
    fn = fn.replace("%%{", "%{")
    for label, key, want_ok in (("hostile", HOSTILE, False), ("valid", SECRET, True)):
        with tempfile.TemporaryDirectory(dir=str(ROOT / ".local-runs")) as t:
            d = pathlib.Path(t)
            stub_dir(d, "curl")
            script = ('fail() { echo "FAIL: $*" >&2; exit 1; }\nFED_DIR=/x ADMIN_ID=a\nAPI_KEY=$(printf %%b %s)\n%s\n%s\n'
                      'admin_call -X POST http://127.0.0.1/\n' % (repr(key.replace("\n", "\\n")), guard, fn))
            r = run_bash(script, d)
            probe("N1 template admin_call %s key: rc ok=%s" % (label, want_ok), (r.returncode == 0) == want_ok, "rc=%d" % r.returncode)
            probe("N1 template admin_call %s key: no extra curl option" % label, curl_stdin_clean(d))
    fs = FED.read_text()
    for fname, arg in (("node_get", "1 mem-1"), ("node_post", "1 e30=")):
        fn = section(fs, fname + "() {", "\n}\n") + "\n}\n"
        with tempfile.TemporaryDirectory(dir=str(ROOT / ".local-runs")) as t:
            d = pathlib.Path(t)
            stub_dir(d, "curl")
            key = d / "api-key"
            key.write_text(HOSTILE + "\n")
            script = ("AUTHOR_ID=au\nnode_sh() { /usr/bin/sed 's#/etc/ai-memory/api-key#%s#' | bash; }\n%s\n%s %s\n"
                      % (key, fn, fname, arg))
            run_bash(script, d)
            probe("N1 %s hostile key: no extra curl option" % fname, curl_stdin_clean(d))
    i = fs.index('  api_key="$(on_node "${PUBLIC_IPS[0]}"')
    j = fs.index("lg_curl()", i)
    blk = fs[i:j]
    for label, key, want_ok in (("hostile", HOSTILE, False), ("valid", SECRET, True)):
        with tempfile.TemporaryDirectory(dir=str(ROOT / ".local-runs")) as t:
            d = pathlib.Path(t)
            stub_dir(d, "curl")
            kf = d / "k"
            kf.write_text(key)
            script = ('die() { echo "DIE: $*" >&2; exit 2; }\non_node() { cat %s; }\nPUBLIC_IPS=(h)\n%s\n'
                      'if [ -n "$api_key" ]; then :; fi\n' % (kf, blk.rsplit("if [ -n", 1)[0]))
            r = run_bash(script, d)
            probe("N1 federate verify %s key: rc ok=%s" % (label, want_ok), (r.returncode == 0) == want_ok, "rc=%d" % r.returncode)


def p1_federate_key_echo():
    fs = FED.read_text()
    i = fs.index('echo "[federate] loadgen bundle: $run_dir"')
    blk = fs[i:fs.index("\n}\n", i)]
    with tempfile.TemporaryDirectory(dir=str(ROOT / ".local-runs")) as t:
        d = pathlib.Path(t)
        rd = d / "run"
        rd.mkdir()
        pre = 'die() { echo "DIE: $*" >&2; exit 2; }\nPUBLIC_IPS=(h)\nrun_dir=%s\n' % rd
        script = pre + 'on_node() { printf "%%s\\n" %s; }\np1f() {\n%s\n}\np1f\n' % (SECRET, blk)
        r = run_bash(script, d)
        probe("P1 key block rc 0", r.returncode == 0, r.stderr[:80])
        probe("P1 key not on stdout or stderr", SECRET not in r.stdout and SECRET not in r.stderr)
        kf = rd / "api-key"
        probe("P1 key written to run_dir/api-key", kf.exists() and SECRET in kf.read_text())
        probe("P1 key file mode 0600", kf.exists() and (kf.stat().st_mode & 0o777) == 0o600)
        kf.unlink()
        tgt = d / "planted-target"
        tgt.write_text("")
        tgt.chmod(0o644)
        kf.symlink_to(tgt)
        run_bash(script, d)
        probe("P1 planted symlink is not followed", tgt.read_text() == "" and not kf.is_symlink())
        kf.unlink()
        kf.write_text("old\n")
        kf.chmod(0o644)
        run_bash(script, d)
        probe("P1 pre-existing 0644 file ends 0600", (kf.stat().st_mode & 0o777) == 0o600)
        r = run_bash(pre + 'on_node() { return 255; }\np1f() {\n%s\n}\np1f\n' % blk, d)
        probe("P1 failed fetch fails closed and leaves no file", r.returncode != 0 and not kf.exists(), "rc=%d" % r.returncode)


def n1_no_locale_ranges():
    guards = [l for l in (TPL.read_text() + FED.read_text()).splitlines() if "{64}" in l and "=~" in l]
    probe("N1 four key guards found", len(guards) == 4, str(len(guards)))
    for g in guards:
        probe("N1 guard has no locale-dependent range: " + g.strip()[:60], re.search(r"\[[^\]]*\w-\w[^\]]*\]", g) is None)


def f2_node_get_id():
    fn = section(FED.read_text(), "node_get() {", "\n}\n") + "\n}\n"
    with tempfile.TemporaryDirectory(dir=str(ROOT / ".local-runs")) as t:
        d = pathlib.Path(t)
        marker = d / "marker-id"
        stub_dir(d, "curl")
        key = d / "api-key"
        key.write_text(SECRET + "\n")
        node_sh = "node_sh() { /usr/bin/sed 's#/etc/ai-memory/api-key#%s#' | bash; }" % key
        r = run_bash("AUTHOR_ID=au\n%s\n%s\nnode_get 1 'x;touch %s'\n" % (node_sh, fn, marker), d)
        probe("F2 node_get refuses a non-plain memory id", r.returncode != 0 and not marker.exists(), "rc=%d" % r.returncode)


def f3_static_pins():
    fed = FED.read_text()
    probe("F3 key file write uses noclobber (O_EXCL)", "set -o noclobber; on_node" in fed)
    i = fed.find("{ set +x; } 2>/dev/null")
    j = fed.find('api_key="$(on_node')
    probe("F3 verify suspends xtrace before the key is read", 0 <= i < j, "%d < %d" % (i, j))
    probe("F3 verify restores xtrace only after the key is cleared", fed.find('api_key=""') < fed.find("[ \"$_fed_xtrace\" = 1 ] && set -x"))


def n3_main_tf():
    tf = (ROOT / "infra/do-hive/main.tf").read_text()
    cond = next(l for l in tf.splitlines() if "ai_memory_image_url == \"\" ||" in l)
    probe("N3 main.tf validation refuses empty/dot path segments and a trailing slash", "&& !can(regex(\"//|/$|/\\\\.\\\\.?(/|$)\"" in cond, cond[-120:])
    probe("N3 main.tf condition has a single top-level alternative", cond.count("||") == 1, cond[:80])


def main():
    (ROOT / ".local-runs").mkdir(exist_ok=True)
    f4_sed()
    f5_admin_call()
    f5_federate()
    f6_spawn()
    n1_curl_config_injection()
    p1_federate_key_echo()
    n3_main_tf()
    n1_no_locale_ranges()
    f2_node_get_id()
    f3_static_pins()
    print("RESULT: %s (%d failed)" % ("FAIL" if FAILS else "PASS", len(FAILS)))
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
