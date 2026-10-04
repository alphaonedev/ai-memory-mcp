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
import time
import threading
import pathlib
import re
import signal
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


def plain_id_def(text):
    """The federate.sh plain_id helper line (verify calls it before node_get), or empty before it existed."""
    return next((l for l in text.splitlines() if l.startswith("plain_id() {")), "")


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
        fn = plain_id_def(fs) + "\n" + section(fs, fname + "() {", "\n}\n") + "\n}\n"
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
             ("https://h/releases//latest", False), ("https://h/o/v1/./a.tgz", False),
             ("https://h/o/v1/a.tgz/", False), ("https://h/", False), ("https://h/o/v1/", False)]
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
        fn = plain_id_def(fs) + "\n" + section(fs, fname + "() {", "\n}\n") + "\n}\n"
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
        if kf.exists() or kf.is_symlink():
            kf.unlink()
        tgt = d / "planted-target"
        tgt.write_text("")
        tgt.chmod(0o644)
        kf.symlink_to(tgt)
        run_bash(script, d)
        probe("P1 planted symlink is not followed", tgt.read_text() == "" and not kf.is_symlink())
        if kf.exists() or kf.is_symlink():
            kf.unlink()
        kf.write_text("old\n")
        kf.chmod(0o644)
        run_bash(script, d)
        probe("P1 pre-existing 0644 file ends 0600", kf.exists() and (kf.stat().st_mode & 0o777) == 0o600)
        r = run_bash(pre + 'on_node() { return 255; }\np1f() {\n%s\n}\np1f\n' % blk, d)
        probe("P1 failed fetch fails closed and leaves no file", r.returncode != 0 and not kf.exists()
              and not list(rd.glob(".api-key.*")), "rc=%d" % r.returncode)
        # A racer that wins between rm -f and the write plants a symlink to a FIFO it reads:
        # bash noclobber opens an existing non-regular target without O_EXCL (#4893).
        fifo = d / "racer-fifo"
        os.mkfifo(str(fifo))
        got = []
        def reader():
            fd = os.open(str(fifo), os.O_RDONLY | os.O_NONBLOCK)
            end = time.time() + 5
            while time.time() < end:
                try:
                    b = os.read(fd, 4096)
                except BlockingIOError:
                    b = b""
                got.append(b)
                time.sleep(0.05)
            os.close(fd)
        th = threading.Thread(target=reader, daemon=True)
        th.start()
        time.sleep(0.2)
        race = pre + ('rm() { command rm "$@"; [ -e "$run_dir/api-key" ] || ln -s %s "$run_dir/api-key"; }\n'
                      'on_node() { printf "%%s\\n" %s; }\np1f() {\n%s\n}\np1f\n') % (fifo, SECRET, blk)
        rp = subprocess.Popen(["bash", "-c", race], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              start_new_session=True, env=dict(os.environ, PATH=str(d) + os.pathsep + os.environ["PATH"]))
        try:
            rp.wait(timeout=8)
        except subprocess.TimeoutExpired:
            os.killpg(rp.pid, signal.SIGKILL)  # the unpatched block blocks reading the FIFO back
            rp.wait()
        th.join(6)
        probe("P1 racer-planted symlink to a FIFO does not receive the key", SECRET.encode() not in b"".join(got))
        # A symlink to a directory planted at api-key: mv without -T would move the key INTO it.
        if kf.exists() or kf.is_symlink():
            kf.unlink()
        pdir = d / "planted-dir"
        pdir.mkdir()
        rdir = pre + ('rm() { command rm "$@"; [ -e "$run_dir/api-key" ] || ln -s %s "$run_dir/api-key"; }\n'
                      'on_node() { printf "%%s\\n" %s; }\np1f() {\n%s\n}\np1f\n') % (pdir, SECRET, blk)
        r = run_bash(rdir, d)
        probe("P1 planted symlink to a directory is replaced, not entered", r.returncode == 0 and not list(pdir.iterdir())
              and kf.is_file() and not kf.is_symlink(), "rc=%d in_dir=%s" % (r.returncode, [p.name for p in pdir.iterdir()]))
        for label, body in (("a trailing extra line", SECRET + "\\nzz\\n"), ("64 non-hex bytes", "z" * 64 + "\\n"),
                            ("a hex first byte then 63 non-hex bytes", "a" + "z" * 63 + "\\n"),
                            ("65 hex bytes", SECRET + "a\\n"), ("the key twice", SECRET + "\\n" + SECRET + "\\n"),
                            ("an empty first line then the key", "\\n" + SECRET), ("nothing", ""),
                            ("the key then a NUL byte", SECRET + "\\0"),
                            ("the key then an empty line (66 bytes)", SECRET + "\\n\\n")):
            if kf.exists() or kf.is_symlink():
                kf.unlink()
            r = run_bash(pre + 'on_node() { printf "%%b" "%s"; }\np1f() {\n%s\n}\np1f\n' % (body, blk), d)
            probe("P1 key file with %s fails closed and leaves no file" % label, r.returncode != 0 and not kf.exists(), "rc=%d" % r.returncode)


def fifo_reader(path, secs, got):
    """Open a FIFO for reading as soon as it exists and collect every byte written to it."""
    def run():
        end = time.time() + secs
        fd = None
        while fd is None and time.time() < end:
            try:
                fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
            except OSError:
                time.sleep(0.02)
        while fd is not None and time.time() < end:
            try:
                got.append(os.read(fd, 4096))
            except BlockingIOError:
                pass
            time.sleep(0.05)
        if fd is not None:
            os.close(fd)
    th = threading.Thread(target=run, daemon=True)
    th.start()
    return th


def run_timeout(script, d, secs):
    """Run bash; return (returncode, timed_out). A blocked open on a FIFO shows as a timeout, not a hang."""
    rp = subprocess.Popen(["bash", "-c", script], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                          start_new_session=True, env=dict(os.environ, PATH=str(d) + os.pathsep + os.environ["PATH"]))
    try:
        return rp.wait(timeout=secs), False
    except subprocess.TimeoutExpired:
        os.killpg(rp.pid, signal.SIGKILL)
        rp.wait()
        return None, True


HOOK = (
    'NAME="$run_dir/.api-key.FORCED"\n'
    'mktemp() { printf "%%s\\n" "$NAME"; }\n'
    'on_node() { : > "$MARK"; printf "%%s\\n" %s; }\n'
    '[() {\n'
    '  builtin [ "$@"; local rc=$?\n'
    '  case "$HK:$*" in\n'
    '    fifo:*"-e $NAME"*) command mkfifo "$NAME" ;;\n'
    '    swap:*"-f /dev/fd/9"*) printf "%%s\\n" %s > "$NAME.new"; command mv -f "$NAME.new" "$NAME" ;;\n'
    '    link:*"-L $NAME"*) command ln -s "$TFILE" "$NAME" ;;\n'
    '    late:*"-ef /dev/fd/9"*) command ln -f "$TFILE" "$NAME.new"; command mv -f "$NAME.new" "$NAME" ;;\n'
    '  esac\n'
    '  return $rc\n'
    '}\n'
)


def p1_temp_entry_fail_closed():
    """#5000: the key is never written to anything but a regular file this run created."""
    fs = FED.read_text()
    i = fs.index('echo "[federate] loadgen bundle: $run_dir"')
    blk = fs[i:fs.index("\n}\n", i)]
    other = "b" * 64
    with tempfile.TemporaryDirectory(dir=str(ROOT / ".local-runs")) as t:
        d = pathlib.Path(t)
        rd = d / "run"
        rd.mkdir()
        mark = d / "on_node.ran"
        name = rd / ".api-key.FORCED"
        kf = rd / "api-key"
        tfile = d / "t-late"
        ready = d / "on_node.ready"
        stub_dir(d, "unused")

        def script(hk, extra=""):
            pre = ('die() { echo "DIE: $*" >&2; exit 2; }\nPUBLIC_IPS=(h)\nrun_dir=%s\nMARK=%s\nHK=%s\nTFILE=%s\n'
                   % (rd, mark, hk, tfile))
            return pre + HOOK % (SECRET, other) + extra + 'p1f() {\n%s\n}\np1f\n' % blk

        def reset():
            for p in list(rd.iterdir()) + [mark]:
                if p.is_dir() and not p.is_symlink():
                    p.rmdir()
                elif p.exists() or p.is_symlink():
                    p.unlink()

        def plant_target(kind):
            if kind == "fifo" or kind == "fifo, no reader" or kind == "symlink to a FIFO":
                f = d / "t-fifo"
                if f.exists():
                    f.unlink()
                os.mkfifo(str(f))
                if kind == "symlink to a FIFO":
                    name.symlink_to(f)
                    return f
                os.mkfifo(str(name))
                return name
            if kind == "symlink to a file":
                f = d / "t-file"
                f.write_text("")
                name.symlink_to(f)
                return f
            if kind == "symlink to a device":
                name.symlink_to("/dev/null")
                return None
            if kind == "dangling symlink":
                name.symlink_to(d / "nowhere")
                return None
            name.mkdir()
            return None

        for kind in ("fifo, no reader", "fifo", "symlink to a FIFO", "symlink to a file", "symlink to a device",
                     "dangling symlink", "directory"):
            reset()
            target = plant_target(kind)
            got = []
            th = fifo_reader(str(target), 4, got) if kind in ("fifo", "symlink to a FIFO") else None
            time.sleep(0.2)
            rc, hung = run_timeout(script("none"), d, 6)
            if th:
                th.join(6)
            body = b"".join(got)
            ok = (not hung) and rc not in (0, None) and not mark.exists() and SECRET.encode() not in body and not kf.exists()
            if kind == "symlink to a file":
                ok = ok and target.read_text() == ""
            probe("P2 %s at the temp name: refused, the key is never produced or written" % kind, ok,
                  "rc=%s hung=%s ran=%s bytes=%d" % (rc, hung, mark.exists(), len(body)))
        # An entry swapped in AFTER the absence check: the opened descriptor is checked before the key is written.
        reset()
        got = []
        th = fifo_reader(str(name), 4, got)
        rc, hung = run_timeout(script("fifo"), d, 6)
        th.join(6)
        probe("P2 a FIFO swapped in after the absence check gets no key", (not hung) and rc not in (0, None)
              and not mark.exists() and SECRET.encode() not in b"".join(got) and not kf.exists(),
              "rc=%s hung=%s ran=%s bytes=%d" % (rc, hung, mark.exists(), len(b"".join(got))))
        reset()
        rc, hung = run_timeout(script("swap"), d, 6)
        probe("P2 the name replaced after the open is refused before the key is written", (not hung) and rc not in (0, None)
              and not mark.exists() and not kf.exists(), "rc=%s hung=%s ran=%s api-key=%s" % (rc, hung, mark.exists(), kf.exists()))
        # A symlink to a regular file planted after the absence checks: noclobber refuses to open it, so
        # the key never reaches the target (without noclobber the -f and -ef checks both pass). An entry
        # swapped in after the -ef check: the key goes to the checked descriptor only, so a write that
        # reopens the name by path puts the key in the target and is red here.
        for hk, label in (("link", "a symlink to a regular file planted after the absence check"),
                          ("late", "an entry swapped in after the -ef check")):
            reset()
            tfile.write_text("")
            rc, hung = run_timeout(script(hk), d, 6)
            probe("P2 %s never receives the key" % label, (not hung) and rc not in (0, None)
                  and SECRET not in tfile.read_text() and not kf.exists(),
                  "rc=%s hung=%s target_bytes=%d" % (rc, hung, len(tfile.read_text())))
            tfile.unlink()
        # An interrupt in the middle of the key write leaves no partial key at the temp name.
        slow = 'on_node() { printf "%%s" %s; : > %s; sleep 30; }\n' % (SECRET[:32], ready)
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            reset()
            if ready.exists():
                ready.unlink()
            rp = subprocess.Popen(["bash", "-c", script("none", slow)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                  start_new_session=True, env=dict(os.environ, PATH=str(d) + os.pathsep + os.environ["PATH"]))
            end = time.time() + 6
            while not ready.exists() and time.time() < end:
                time.sleep(0.05)
            started = ready.exists()
            os.killpg(rp.pid, sig)
            try:
                rc, hung = rp.wait(timeout=6), False
            except subprocess.TimeoutExpired:
                os.killpg(rp.pid, signal.SIGKILL)
                rc, hung = rp.wait(), True
            left = sorted(q.name for q in rd.iterdir())
            probe("P2 %s during the key write leaves no temp file and no api-key" % sig.name, started and not hung
                  and rc not in (0, None) and not left, "started=%s rc=%s hung=%s left=%s" % (started, rc, hung, left))
        reset()
        rc, hung = run_timeout(script("none"), d, 6)
        # An unplanted name still works (the probes above are not red because the block is broken).
        probe("P2 an unplanted temp name is accepted", rc == 0 and kf.is_file() and SECRET in kf.read_text()
              and (kf.stat().st_mode & 0o777) == 0o600, "rc=%s" % rc)


def failure_lines_4999():
    """#4999: a failure line shows a bounded printable excerpt of a node reply, never the raw bytes."""
    fs = FED.read_text()
    i = fs.find("safe_excerpt() {")
    j = fs.find("# node_get <idx0>", i)
    defs = fs[i:j] if 0 <= i < j else ""
    probe("V1 safe_excerpt and safe_code exist", bool(defs))
    longtok = "Zm9vYmFyYmF6cXV4" * 6
    hostile = ('{"note":"see hunter2hunter ok","pad":"%s","error":"bad\x1b[31m\x01\x07 thing\x7f","id":"\xc3\xa9\xe2\x82\xac",'
               '"k":"%s","t":"%s","Authorization":"Bearer short-tok","pem":"-----BEGIN PRIVATE KEY-----"}' % ("ab " * 100, SECRET, longtok))
    with tempfile.TemporaryDirectory(dir=str(ROOT / ".local-runs")) as t:
        d = pathlib.Path(t)
        sc = ("api_key=hunter2hunter\n%s\nb=$'%s'\nsafe_excerpt \"$b\"; echo\nsafe_code $'20\\x1b[31m1'; echo\nsafe_code 201; echo\n"
              % (defs, hostile.replace("\\", "\\\\").replace("'", "\\'").replace("\x1b", "\\x1b").replace("\x01", "\\x01")
                 .replace("\x07", "\\x07").replace("\x7f", "\\x7f")))
        r = run_bash(sc.replace("short-tok", "short-tok hunter2hunter"), d)
        out = r.stdout
        lines = out.split("\n")
        first = lines[0] if lines else ""
        probe("V1 excerpt has no control or non-ASCII byte", all(32 <= ord(c) < 127 for c in out.replace("\n", "")) and bool(first), repr(out[:60]))
        probe("V1 excerpt carries the byte count", first.startswith(str(len(hostile.replace("short-tok", "short-tok hunter2hunter").encode("utf-8"))) + " bytes: "), first[:30])
        probe("V1 excerpt is bounded", len(first) <= 140, str(len(first)))
        probe("V1 excerpt never holds the key, a token run, a credential word value or the api key by value",
              SECRET not in out and longtok not in out and "short-tok" not in out and "hunter2hunter" not in out
              and "PRIVATE KEY" not in out.upper(), first[:80])
        probe("V1 safe_code passes a status and excerpts anything else", lines[2:3] == ["201"] and "bytes:" in (lines[1] if len(lines) > 1 else "")
              and "\x1b" not in out, repr(lines[1:3]))
        # Behaviour at the real sites: the quorum and the signed-write failure lines.
        for var, cvar, jvar, start, end in (
                ("quorum", "qcode", "qjson", '  case "$qcode" in', '  if [ -n "$QID" ] && ! plain_id'),
                ("signed", "scode", "sjson", '      SID=$(echo "$sjson" | jq -r \'.id // empty\' 2>/dev/null)\n', '      if [ -n "$SID" ]; then\n        lvl=""')):
            a = fs.find(start)
            b = fs.find(end, a) if a >= 0 else -1
            snip = fs[a:b] if 0 <= a < b else ""
            # set -u as in federate.sh: a site that reads an unset flag is red here, not only in production.
            sc = ("set -u\napi_key=''\n%s\nok() { echo \"OK $*\"; }\nno() { echo \"NO $*\"; }\nQID=''\nSID=''\n%s='500'\n%s=$'%s'\n%s\n"
                  % (defs + plain_id_def(fs), cvar, jvar, hostile.replace("\\", "\\\\").replace("'", "\\'").replace("\x1b", "\\x1b")
                     .replace("\x01", "\\x01").replace("\x07", "\\x07").replace("\x7f", "\\x7f"), snip))
            r = run_bash(sc, d)
            out = r.stdout
            probe("V1 %s failure line prints no raw node bytes" % var, 0 <= a < b and "NO " in out and "bytes:" in out and SECRET not in out
                  and longtok not in out and all(32 <= ord(c) < 127 for c in out.replace("\n", "")), out.strip()[:80])
    # Each redaction rule on its own: the trigger sits inside the first 120 bytes and no other rule can
    # mask it, so dropping or loosening any one rule is a FAIL line (a hostile reply padded past the cut
    # tested only the cut).
    rules = (("a 20-character token run", "", '{"t":"%s"}' % ("q7" * 10), "q7" * 10),
             ("an upper-case token run", "", '{"t":"%s"}' % ("Q7" * 11), "q7" * 11),
             ("an api_key value", "", '{"api_key":"x9z"}', "x9z"),
             ("an Authorization value", "", '{"h":"Authorization: x9z"}', "x9z"),
             ("a bearer value", "", '{"h":"bearer x9z"}', "x9z"),
             ("a password value", "", '{"password":"x9z"}', "x9z"),
             ("a passwd value", "", '{"passwd":"x9z"}', "x9z"),
             ("a secret value", "", '{"secret":"x9z"}', "x9z"),
             ("a token value", "", '{"token":"x9z"}', "x9z"),
             ("a private value", "", '{"private":"x9z"}', "x9z"),
             ("a PEM key header", "", "-----BEGIN EC KEY----- x9z", "x9z"),
             ("the api key by value", "hunter2hunter", '{"k":"hunter2hunter"}', "hunter2hunter"))
    with tempfile.TemporaryDirectory(dir=str(ROOT / ".local-runs")) as t:
        d = pathlib.Path(t)
        for label, key, body, leak in rules:
            (d / "body").write_text(body)
            r = run_bash("api_key='%s'\n%s\nb=$(cat %s)\nsafe_excerpt \"$b\"\n" % (key, defs, d / "body"), d)
            low = r.stdout.lower()
            probe("V2 excerpt redacts %s" % label, bool(defs) and "bytes: " in low and leak.lower() not in low,
                  r.stdout.strip()[:80])
        # The key itself, in every spelling a node could send: the failure line must carry none of it.
        # The comparison is on the reply with separators and case removed, so no spelling needs its own
        # pattern; each probe below is a different way to write the same 64 digits.
        import base64
        key = SECRET
        grp = lambda s, n, sep: sep.join(s[k:k + n] for k in range(0, len(s), n))
        raw_b64 = base64.b64encode(bytes.fromhex(key)).decode()
        txt_b64 = base64.b64encode(key.encode()).decode()
        spellings = (("space groups of 16", grp(key, 16, " ")),
                     ("space groups of 4", grp(key, 4, " ")),
                     ("dot groups of 8", grp(key, 8, ".")),
                     ("dash groups of 8", grp(key, 8, "-")),
                     ("colon pairs", grp(key, 2, ":")),
                     ("newline groups of 16", grp(key, 16, "\n")),
                     ("tab and comma groups", grp(key, 8, "\t,")),
                     ("upper case", key.upper()),
                     ("mixed case in groups", grp("".join(c.upper() if n % 2 else c for n, c in enumerate(key)), 16, " ")),
                     ("a letter as the separator", grp(key, 16, "zz")),
                     ("inside a JSON string", '{"detail":"key is %s now"}' % grp(key, 32, " ")),
                     ("base64 of the text", txt_b64),
                     ("base64 of the text in groups of 10", grp(txt_b64, 10, " ")),
                     ("base64 of the raw bytes", raw_b64),
                     ("base64 of the raw bytes in groups of 8", grp(raw_b64, 8, " ")),
                     ("url-safe base64 of the raw bytes", raw_b64.replace("+", "-").replace("/", "_").rstrip("=")),
                     ("ASCII hex of the text in pairs", grp(key.encode().hex(), 2, " ")))
        for label, body in spellings:
            (d / "body").write_text(body)
            r = run_bash("api_key='%s'\n%s\nb=$(cat %s)\nsafe_excerpt \"$b\"\n" % (key, defs, d / "body"), d)
            out = r.stdout.lower()
            sq = "".join(c for c in out if c.isalnum())
            probe("V2 excerpt carries no key spelled as %s" % label, bool(defs) and "bytes: " in out
                  and key[:12] not in sq and txt_b64[:12].lower() not in sq and raw_b64[:12].lower() not in sq
                  and key.encode().hex()[:12] not in sq, r.stdout.strip()[:80])
        # A reply that merely looks like a key is still shown (the compare is not a blanket redaction).
        other = "".join("0123456789abcdef"[(n * 7 + 3) % 16] for n in range(64))
        for label, body in (("an unrelated 64-digit hex value in groups", grp(other, 16, " ")),
                            ("a short prefix of the key", key[:20] + " is not the key")):
            (d / "body").write_text(body)
            r = run_bash("api_key='%s'\n%s\nb=$(cat %s)\nsafe_excerpt \"$b\"\n" % (key, defs, d / "body"), d)
            probe("V2 excerpt still shows %s" % label, "bytes: " in r.stdout and "key material" not in r.stdout, r.stdout.strip()[:80])
        # The hostile reply above is padded past the 120-byte window, so each filter is also probed with
        # a short reply whose hostile part sits inside the window (otherwise truncation alone passes).
        for label, raw, bad in (("control and non-ASCII bytes", "e:bad\\x1b[31m\\x01\\x07 \\xc3\\xa9\\xe2\\x82\\xac end", None),
                                ("a token run", "t:" + longtok + " end", longtok[:20].lower()),
                                ("a credential word value", "Authorization: Bearer short-tok", "short-tok")):
            r = run_bash("api_key=''\n%s\nsafe_excerpt $'%s'\n" % (defs, raw), d)
            o = r.stdout
            probe("V1 short reply with %s is filtered inside the window" % label, bool(defs) and " bytes: " in o
                  and all(32 <= b < 127 for b in o.encode("utf-8", "surrogateescape"))
                  and (bad is None or bad not in o.lower()), repr(o[:80]))
    # No failure line in verify interpolates a node-derived value unsanitised.
    vi = fs.index("\nverify() {")
    raw = []
    for n, l in enumerate(fs[vi:].splitlines()):
        if re.search(r'\bno "', l):
            rest = re.sub(r'\$\(safe_(?:code|excerpt) "\$\w+"\)', "", l[re.search(r'\bno "', l).start():])
            if re.search(r"\$\{?(?:code|qcode|scode|lvl|qjson|sjson|versions|resp|sresp)\b", rest):
                raw.append(n)
    probe("V1 no failure line in verify prints a node-derived value unsanitised", not raw, str(raw))


def n1_no_locale_ranges():
    guards = [l for l in (TPL.read_text() + FED.read_text()).splitlines() if "{64}" in l and "=~" in l]
    probe("N1 four key guards found", len(guards) == 4, str(len(guards)))
    for g in guards:
        probe("N1 guard has no locale-dependent range: " + g.strip()[:60], re.search(r"\[[^\]]*\w-\w[^\]]*\]", g) is None)
    # Every bash =~ check in the three shipped shell surfaces (the key guards, the node_get id
    # check, the spawn.sh URL check): a range matches non-ASCII code points under UTF-8 locales.
    allre = [l for l in (TPL.read_text() + FED.read_text() + SPAWN.read_text()).splitlines() if "=~" in l and not l.lstrip().startswith("#")]
    probe("N1 seven =~ checks found", len(allre) == 7, str(len(allre)))
    for g in allre:
        probe("N1 =~ check has no locale-dependent range: " + g.strip()[:60], re.search(r"\[[^\]]*\w-\w[^\]]*\]", g) is None)


def f2_node_get_id():
    fn = plain_id_def(FED.read_text()) + "\n" + section(FED.read_text(), "node_get() {", "\n}\n") + "\n}\n"
    with tempfile.TemporaryDirectory(dir=str(ROOT / ".local-runs")) as t:
        d = pathlib.Path(t)
        marker = d / "marker-id"
        stub_dir(d, "curl")
        key = d / "api-key"
        key.write_text(SECRET + "\n")
        node_sh = "node_sh() { /usr/bin/sed 's#/etc/ai-memory/api-key#%s#' | bash; }" % key
        r = run_bash("AUTHOR_ID=au\n%s\n%s\nnode_get 1 'x;touch %s'\n" % (node_sh, fn, marker), d)
        probe("F2 node_get refuses a non-plain memory id", r.returncode != 0 and not marker.exists(), "rc=%d" % r.returncode)
        # verify names the cause (a refused id) instead of retrying it as a replication failure.
        fs = FED.read_text()
        for var, start, end in (("QID", '  if [ -n "$QID" ] && ! plain_id "$QID"; then', "  # A4 --"),
                                ("SID", '      SID=$(echo "$sjson" | jq -r \'.id // empty\' 2>/dev/null)\n', '      if [ -n "$SID" ]; then\n        lvl=""')):
            # find, not index: a moved or renamed anchor is a FAIL line, never a traceback that skips later probes.
            # SID starts after its assignment, so the snippet holds both the id check and the accept line
            # in source order: a check moved after the accept line prints OK and turns this red.
            i = fs.find(start)
            j = fs.find(end, i) if i >= 0 else -1
            snip = fs[i + (len(start) if var == "SID" else 0):j] if 0 <= i < j else ""
            # set -u as in federate.sh: a snippet that reads an unset flag is red here, not only in production.
            sc = ("set -u\n%s\nok() { echo OK; }\nno() { echo \"NO $*\"; }\nnode_get() { echo CALLED; }\nsleep() { :; }\n"
                  "scode=201\nsjson='{}'\n%s='x;touch %s'\n%s\necho \"after=[$%s]\"\n" % (plain_id_def(fs), var, marker, snip, var))
            r = run_bash(sc, d)
            probe("F2 verify reports a non-plain %s as a refused id, once, and never reads it back" % var,
                  0 <= i < j and "not a plain id" in r.stdout and r.stdout.count("NO ") == 1 and "OK" not in r.stdout
                  and "CALLED" not in r.stdout and "after=[]" in r.stdout and not marker.exists(), r.stdout.strip()[:80])
        # A failed signed write that returns no id: exactly one failure line naming the code, run under
        # set -u. srefused is read on this path only, so a dropped srefused="" is an unbound variable here.
        i = fs.find('      SID=$(echo "$sjson" | jq -r \'.id // empty\' 2>/dev/null)\n')
        j = fs.find('      if [ -n "$SID" ]; then\n        lvl=""', i) if i >= 0 else -1
        snip = fs[i + len('      SID=$(echo "$sjson" | jq -r \'.id // empty\' 2>/dev/null)\n'):j] if 0 <= i < j else ""
        sc = ("set -u\n%s\nok() { echo OK; }\nno() { echo \"NO $*\"; }\nnode_get() { echo CALLED; }\nsleep() { :; }\n"
              "scode=500\nsjson='{}'\nSID=''\n%s\necho done\n" % (plain_id_def(fs) + "\n" + fs[fs.find("safe_excerpt() {"):fs.find("# node_get <idx0>")], snip))
        r = run_bash(sc, d)
        probe("#4957 a failed signed write with no id is one failure line, with srefused initialised under set -u",
              0 <= i < j and r.returncode == 0 and "done" in r.stdout and r.stdout.count("NO ") == 1 and "'500'" in r.stdout
              and "OK" not in r.stdout and "unbound" not in r.stderr, (r.stdout + r.stderr).strip()[:100])


def f2_id_lists_agree():
    fs = FED.read_text()
    lists = re.findall(r"\^(\[[^\]]*\])\{1,64\}\$", "\n".join(l for l in fs.splitlines() if "=~" in l and "1,64" in l))
    probe("F2 plain_id and node_get accept the same id characters", len(lists) == 2 and set(lists[0]) == set(lists[1]), str(len(lists)))


def f3_static_pins():
    fed = FED.read_text()
    probe("F3 key file write uses noclobber (O_EXCL) on an unpredictable name", "set -o noclobber" in fed
          and 'mktemp -u "$run_dir/.api-key.' in fed and 'mv -f -T -- "$keytmp" "$keyf"' in fed
          and 'exec 9> "$keytmp"' in fed and "'cat /etc/ai-memory/api-key' >&9" in fed)
    i = fed.find("{ set +x; } 2>/dev/null")
    j = fed.find('api_key="$(on_node')
    probe("F3 verify suspends xtrace before the key is read", 0 <= i < j, "%d < %d" % (i, j))
    k, x = fed.find('api_key=""'), fed.find("[ \"$_fed_xtrace\" = 1 ] && set -x")
    probe("F3 verify restores xtrace only after the key is cleared", 0 <= k < x, "%d < %d" % (k, x))
    # Behaviour, not text: run the verify key read under bash -x and look for the key in the trace.
    seg = section(fed, "  # The key must not reach an xtrace log", "  if [ -n \"$api_key\" ]; then")
    with tempfile.TemporaryDirectory(dir=str(ROOT / ".local-runs")) as t:
        d = pathlib.Path(t)
        r = run_bash('set -x\ndie() { echo "DIE: $*" >&2; exit 2; }\nPUBLIC_IPS=(h)\n'
                     'on_node() { printf "%%s\\n" %s; }\nvf() {\n%s\n}\nvf\necho "xt=$_fed_xtrace"\n' % (SECRET, seg), d)
        k2 = fed.find('  api_key=""\n')
        tail = fed[k2:fed.index('  [ "$fail" -eq 0 ]\n}\n', k2)] if k2 >= 0 else ""
        r2 = run_bash('set -x\nfail=0\napi_key=%s\n_fed_xtrace=1\nvf() {\n%s\n}\nvf\n'
                      'case $- in *x*) X=on ;; *) X=off ;; esac\n{ set +x; } 2>/dev/null\necho "X=$X K=${#api_key}"\n' % (SECRET, tail), d)
        probe("F3 verify tail clears the key and restores xtrace", r2.returncode == 0 and "X=on K=0" in r2.stdout,
              r2.stdout.strip()[-20:] if "X=on K=0" not in r2.stdout else "")
        probe("F3 verify key read under bash -x leaves no key in the trace", r.returncode == 0 and "xt=1" in r.stdout
              and SECRET not in r.stderr and SECRET not in r.stdout, "rc=%d" % r.returncode)


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
    p1_temp_entry_fail_closed()
    failure_lines_4999()
    n3_main_tf()
    n1_no_locale_ranges()
    f2_node_get_id()
    f2_id_lists_agree()
    f3_static_pins()
    print("RESULT: %s (%d failed)" % ("FAIL" if FAILS else "PASS", len(FAILS)))
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
