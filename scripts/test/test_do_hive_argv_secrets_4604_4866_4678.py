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
                          preexec_fn=lambda: [signal.signal(s, signal.SIG_DFL) for s in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)],
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
            # A caller that started this test under nohup or in the background passes these signals as
            # ignored; the child must see the defaults, as an interactive run does.
            rp = subprocess.Popen(["bash", "-c", script("none", slow)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                  preexec_fn=lambda: [signal.signal(s, signal.SIG_DFL) for s in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)],
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
            # #5151: the trap's own exit status (130), not only any non-zero status.
            probe("P2 %s during the key write leaves no temp file and no api-key, and exits 130" % sig.name, started and not hung
                  and rc == 130 and not left, "started=%s rc=%s hung=%s left=%s" % (started, rc, hung, left))
        # After the block succeeds the trap is gone: a later interrupt ends the run by the default
        # action (signal death), it does not run the key-file cleanup or exit 130.
        reset()
        okscript = script("none").replace("p1f\n", "p1f\nkill -INT $$\nsleep 5\n") if script("none").endswith("p1f\n") else ""
        rc, hung = run_timeout(okscript, d, 8) if okscript else (None, True)
        probe("P2 the interrupt trap is cleared once the key is written", (not hung) and rc == -signal.SIGINT and kf.exists(),
              "rc=%s hung=%s api-key=%s" % (rc, hung, kf.exists()))
        reset()
        rc, hung = run_timeout(script("none"), d, 6)
        # An unplanted name still works (the probes above are not red because the block is broken).
        probe("P2 an unplanted temp name is accepted", rc == 0 and kf.is_file() and SECRET in kf.read_text()
              and (kf.stat().st_mode & 0o777) == 0o600, "rc=%s" % rc)


REPLY_HELPERS = ("reply_status", "reply_len", "reply_version")
# The only paths from a node-derived value to a PASS/FAIL/REFUSE line or a terminal echo/printf (#4999,
# 5-agent vote 4d3ea1c5). The set is closed: the test fails if federate.sh defines another reply_* helper
# or if any other construct carries a node value to the terminal.
ALLOWED = frozenset(REPLY_HELPERS)
HOSTILE_LEN = 64


def reply_defs(fs):
    """The closed-world reply helpers in federate.sh, or empty when they are absent."""
    i = fs.find("reply_status() {")
    j = fs.find("# node_get <idx0>", i) if i >= 0 else -1
    return fs[i:j] if 0 <= i < j else ""


def bq(b):
    """A bash ANSI-C literal that yields exactly the bytes b (no NUL)."""
    return "$'" + "".join("\\x%02x" % c for c in b) + "'"


def run_bash_bytes(script, d, lc="C.UTF-8", extra_env=None):
    env = dict(os.environ, PATH=str(d) + os.pathsep + os.environ["PATH"], LOGDIR=str(d), LC_ALL=lc)
    env.update(extra_env or {})
    return subprocess.run(["bash", "-c", script], capture_output=True, stdin=subprocess.DEVNULL, env=env)


def hostile_replies():
    """Node replies of one byte length: the key, a postgres URL with a password, bytes that forge a
    terminal line, seeded random bytes and a 2xx-looking value. None holds a NUL or a newline."""
    import random
    def pad(b):
        assert len(b) <= HOSTILE_LEN
        return b + b"~" * (HOSTILE_LEN - len(b))
    rnd = random.Random(4999)
    pool = [c for c in range(1, 256) if c != 10]
    return (("the node API key", SECRET.encode()),
            ("a postgres URL with a password", pad(b'{"e":"postgres://aimemory:x9zQ@10.20.0.5:5432/aimemory"}')),
            ("ESC and control bytes that forge a PASS line", pad(b"\x1b[2K\r\x1b[32mPASS: node 1 PostgreSQL 18.6\x1b[0m\x07\x08\x7f\x01")),
            ("seeded random bytes", bytes(rnd.choice(pool) for _ in range(HOSTILE_LEN))),
            ("a 2xx-looking value that carries the key", pad(b"204 x-api-key: " + SECRET[:40].encode())))


def clean_line(b):
    """True when a byte line is printable ASCII and carries no secret, password or hostile marker, in any case."""
    low = b.lower()
    return (all(32 <= c < 127 for c in b) and SECRET.encode() not in low and SECRET[:16].encode() not in low
            and b"x9zq" not in low and b"x-api-key" not in low)


def failure_lines_4999():
    """#4999 closed world: no byte of a node reply reaches a failure line; status, length, version only."""
    fs = FED.read_text()
    defs = reply_defs(fs)
    probe("V1 the closed-world reply helpers exist (reply_status, reply_len, reply_version)", bool(defs)
          and all(h + "() {" in defs for h in REPLY_HELPERS))
    probe("V1 the excerpt helpers are deleted (safe_excerpt, reply_carries_key, safe_code)",
          not re.search(r"\b(?:safe_excerpt|reply_carries_key|safe_code)\b", fs))
    defined = set(re.findall(r"^(reply_\w+)\(\) \{", fs, re.M))
    probe("V1 the allow-list is exactly the reply_* helpers federate.sh defines", defined == set(ALLOWED), str(sorted(defined)))
    with tempfile.TemporaryDirectory(dir=str(ROOT / ".local-runs")) as t:
        d = pathlib.Path(t)
        # reply_status: three ASCII digits, or the fixed word.
        status_cases = ((b"200", b"200"), (b"201", b"201"), (b"2000", b"non-status"), (b"20", b"non-status"),
                        (b"", b"non-status"), (b"20\x1b[31m", b"non-status"), (b"\xd9\xa2\xd9\xa0\xd9\xa0", b"non-status"),
                        (b"\xef\xbc\x92\xef\xbc\x90\xef\xbc\x90", b"non-status"), (b" 200", b"non-status"),
                        (b"200\n500", b"non-status"), (b"2\xc3\xa90", b"non-status"), (b"2x0", b"non-status"))
        # reply_version: 1 to 3 dot-separated groups of 1 to 3 ASCII digits; anything else is a byte count.
        ver_ok = (b"1", b"18", b"180", b"18.6", b"1.8.0", b"0.8.6", b"999.999.999")
        ver_bad = (b"", b"1234", b"1.2.3.4", b"18.6.1.0", b"1..2", b".1", b"1.", b" 18.6", b"18.6 ", b"1e3",
                   b"\xd9\xa1\xd9\xa8.6", b"\xef\xbc\x91\xef\xbc\x98", b"18.6x", b"-1", b"18,6", b"12345678901234567890",
                   b"1.2345", b"18.6\x1b[0m", b"18.\xc3\xa96", b"1\n2", b"*", b"[0-9]", b"?")
        for lc in ("C.UTF-8", "C"):
            sc = "set -u\n" + defs + "\n"
            for raw, _ in status_cases:
                sc += "reply_status %s; echo\n" % bq(raw)
            for raw in ver_ok + ver_bad:
                sc += "reply_version %s %s; echo\n" % (bq(raw), bq(raw))
            sc += "reply_len %s; echo\nreply_len ''; echo\n" % bq("\xe9\u20ac".encode())
            r = run_bash_bytes(sc, d, lc)
            lines = r.stdout.split(b"\n")
            got_s = lines[:len(status_cases)]
            want_s = [w for _, w in status_cases]
            probe("V1 reply_status prints 3 ASCII digits or non-status, never other bytes (LC_ALL=%s)" % lc,
                  bool(defs) and r.returncode == 0 and got_s == want_s, repr([g for g, w in zip(got_s, want_s) if g != w][:4]))
            got_v = lines[len(status_cases):len(status_cases) + len(ver_ok) + len(ver_bad)]
            want_v = list(ver_ok) + [b"%d bytes" % len(x) for x in ver_bad]
            bad = [(x, g) for x, g, w in zip(ver_ok + ver_bad, got_v, want_v) if g != w]
            probe("V1 reply_version accepts 1-3 groups of 1-3 digits and prints a byte count otherwise (LC_ALL=%s)" % lc,
                  bool(defs) and len(got_v) == len(want_v) and not bad, repr(bad[:4]))
            tail = lines[len(status_cases) + len(ver_ok) + len(ver_bad):]
            probe("V1 reply_len counts bytes, not characters (LC_ALL=%s)" % lc, tail[:2] == [b"5 bytes", b"0 bytes"], repr(tail[:2]))
        hostile = hostile_replies()
        probe("V1 the hostile replies are equal in length and hold no NUL or newline",
              len({len(h) for _, h in hostile}) == 1 and not any(b"\x00" in h or b"\n" in h for _, h in hostile))
        # The two HTTP sites, run whole with each hostile reply as the body and as the status.
        for site, cvar, jvar, start, end, pat in (
                ("quorum", "qcode", "qjson", '  case "$qcode" in', '  if [ -n "$QID" ] && ! plain_id',
                 rb"^NO quorum write at node 1 got '(\d{3}|non-status)' \((\d+) bytes\)$"),
                ("signed", "scode", "sjson", '      srefused=""\n', '      if [ -n "$SID" ]; then\n        lvl=""',
                 rb"^NO signed write at node 1 got '(\d{3}|non-status)' \((\d+) bytes\)$")):
            a = fs.find(start)
            b = fs.find(end, a) if a >= 0 else -1
            snip = fs[a:b] if 0 <= a < b else ""
            for codemode in ("500", "hostile"):
                outs = {}
                for lc in ("C.UTF-8", "C"):
                    for label, h in hostile:
                        code = bq(h) if codemode == "hostile" else "'500'"
                        sc = ("set -u\n%s\n%s\nok() { echo \"OK $*\"; }\nno() { echo \"NO $*\"; }\nQID=''\nSID=''\n%s=%s\n%s=%s\n%s\n"
                              % (defs, plain_id_def(fs), cvar, code, jvar, bq(h), snip))
                        r = run_bash_bytes(sc, d, lc)
                        outs[(lc, label)] = r.stdout + b"|" + r.stderr
                lines = set(outs.values())
                one = next(iter(lines))
                fl = one.split(b"|")[0].rstrip(b"\n")
                want = b"'500'" if codemode == "500" else b"'non-status'"
                probe("V1 %s failure line is byte-identical for every equal-length hostile reply (status %s)" % (site, codemode),
                      bool(snip) and len(lines) == 1, "%d distinct" % len(lines))
                probe("V1 %s failure line matches the fixed pattern (status %s)" % (site, codemode),
                      bool(snip) and re.match(pat, fl) is not None and want in fl and fl.endswith(b"(%d bytes)" % HOSTILE_LEN),
                      repr(fl[:100]))
                probe("#5152 %s failure line never prints the URL password or the key (status %s)" % (site, codemode),
                      bool(snip) and all(clean_line(v.replace(b"\n", b" ").replace(b"|", b" ")) for v in outs.values()))
        # The three psql version lines: a hostile token prints the byte count of the whole reply.
        vb = version_block(fs)
        outs = {}
        for lc in ("C.UTF-8", "C"):
            for label, h in hostile:
                reply = b"Q" + h + b"\nage=Q" + h + b"\nvector=Q" + h
                r = run_versions_bytes(fs, defs, reply, d, lc)
                outs[(lc, label)] = r.stdout + b"|" + r.stderr
        lines = set(outs.values())
        one = next(iter(lines)).split(b"|")[0].splitlines()
        vpat = rb"\(got (?:\d{1,3}(?:\.\d{1,3}){0,2}|\d+ bytes)\)$"
        probe("V1 version failure lines are byte-identical for every equal-length hostile reply", bool(vb) and len(lines) == 1,
              "%d distinct" % len(lines))
        probe("V1 version failure lines match the fixed pattern", bool(vb) and len(one) == 3
              and all(l.startswith(b"NO ") and re.search(vpat, l) for l in one)
              and all(l.endswith(b"(got %d bytes)" % (3 * HOSTILE_LEN + 16)) for l in one), repr(one))
        probe("#5152 version failure lines never print the URL password or the key",
              all(clean_line(v.replace(b"\n", b" ").replace(b"|", b" ")) for v in outs.values()))
        r = run_versions_bytes(fs, defs, b"17.2\nage=1.7.0\nvector=0.8.5", d, "C.UTF-8")
        probe("V1 a benign version mismatch names the version token", r.stdout.splitlines() == [
            b"NO node 1 PostgreSQL is not 18.6 (got 17.2)", b"NO node 1 AGE is not 1.8.0 (got 1.7.0)",
            b"NO node 1 pgvector is not 0.8.6 (got 0.8.5)"], repr(r.stdout[:160]))
        r = run_versions_bytes(fs, defs, b"17.2.1.0\nage=1.8.0.1\nvector=12345", d, "C.UTF-8")
        probe("V1 an over-long version token prints the byte count, not the token", r.stdout.splitlines() == [
            b"NO node 1 PostgreSQL is not 18.6 (got 33 bytes)", b"NO node 1 AGE is not 1.8.0 (got 33 bytes)",
            b"NO node 1 pgvector is not 0.8.6 (got 33 bytes)"], repr(r.stdout[:160]))
        verify_canary(fs, d, hostile)
    closed_world_taint(fs)


def run_versions_bytes(fs, defs, reply, d, lc):
    (d / "versions.reply").write_bytes(reply)
    sc = ("set -u\n%s\nok() { echo \"OK $*\"; }\nno() { echo \"NO $*\"; }\nNODE_COUNT=1\napi_key=''\n"
          "node_sh() { cat %s; }\n%s\n" % (defs, d / "versions.reply", version_block(fs)))
    return run_bash_bytes(sc, d, lc)


def verify_canary(fs, d, hostile):
    """Run the whole verify step with every node channel answering one hostile reply: the terminal output
    is byte-identical across replies and carries no reply byte."""
    k = fs.find("# --- main")
    (d / "fed-prefix.sh").write_text(fs[:k] if k > 0 else "")
    (d / "signer").write_text("#!/bin/bash\necho sig\n")
    (d / "signer").chmod(0o755)
    for mode in ("all-hostile", "id-then-hostile-level"):
        outs = {}
        for lc in ("C.UTF-8", "C"):
            for label, h in hostile:
                # A JSON-safe variant for the attest_level string (jq decodes it back to these bytes).
                hj = bytes(c if c >= 32 and c != 127 and c < 128 and c not in (34, 92) else 0x3f for c in h)
                if mode == "all-hostile":
                    post = "printf '%s\\n%s' \"$H\" \"$H\""
                    get = "printf '%s' \"$H\""
                else:
                    post = "printf '%s\\n%s' '{\"id\":\"abc\"}' 201"
                    get = "printf '{\"id\":\"abc\",\"metadata\":{\"attest_level\":\"%%s\"}}' %s" % bq(hj)
                sc = ("set -u\nH=%s\nV=$'Q'\"$H\"$'\\nage=Q'\"$H\"$'\\nvector=Q'\"$H\"\n"
                      "source %s\n"
                      "NODE_COUNT=2\nPUBLIC_IPS=(h1 h2)\nPEER_URLS=(https://p1:9077 https://p2:9077)\n"
                      "node_sh() { local s; s=$(cat); case \"$s\" in *server_version*) printf '%%s' \"$V\" ;; *) printf '%%s' \"$H\" ;; esac; }\n"
                      "on_node() { case \"$2\" in *api-key*) printf '%%s\\n' %s ;; *) printf '%%s' \"$H\" ;; esac; }\n"
                      # curl as the real one: -w writes to stdout, -o /dev/null drops the body.
                      "curl() { cat >/dev/null; case \" $* \" in *' -w '*) printf '%%s' \"$H\" ;; *' -o '*) : ;; *) printf '%%s' \"$H\" ;; esac; }\n"
                      "node_post() { %s; }\nnode_get() { %s; }\nsleep() { :; }\n"
                      "verify; echo \"rc=$?\"\n"
                      % (bq(h), d / "fed-prefix.sh", SECRET, post, get))
                r = run_bash_bytes(sc, d, lc, {"SIGNER": str(d / "signer"), "AUTHOR_KEY_DIR": str(d), "OUT_DIR": str(d / "out")})
                outs[(lc, label)] = r.stdout + b"|" + r.stderr
        distinct = set(outs.values())
        one = next(iter(distinct))
        probe("V1 whole verify output is byte-identical for every equal-length hostile reply (%s)" % mode,
              k > 0 and len(distinct) == 1 and b"federate verify:" in one, "%d distinct; %r" % (len(distinct), one[-120:]))
        probe("#5152 whole verify output carries no key, URL password, ESC or non-ASCII byte (%s)" % mode,
              k > 0 and all(clean_line(v.replace(b"\n", b" ").replace(b"|", b" ")) for v in outs.values()))
        nlines = [l for l in one.split(b"|")[0].splitlines() if l.startswith(b"FAIL: ")]
        probe("V1 whole verify reports the hostile replies as failures (%s)" % mode, len(nlines) >= (6 if mode == "all-hostile" else 1),
              str(len(nlines)))


TAINT_SOURCES = ("on_node", "node_sh", "node_get", "node_post", "curl", "lg_curl", "ssh", "scp")
SINKS = ("ok", "no", "die", "echo", "printf")


def _segments(line, name_re):
    """(command, argument text) for each sink command in a logical line; quote- and $()-aware."""
    out = []
    for m in re.finditer(r"(?:^|(?<=[\s;(&|]))(%s)(?=\s)" % name_re, line):
        before = line[:m.start()]
        # Skip a match that sits inside a quoted string (a message naming a command).
        if before.count('"') % 2 == 1 and "$(" not in before[before.rfind('"'):]:
            continue
        i, depth, quote, end = m.end(), 0, None, len(line)
        while i < len(line):
            c = line[i]
            if c == "\\":
                i += 2
                continue
            if quote == "'":
                quote = None if c == "'" else quote
            elif line.startswith("$(", i):
                depth += 1
                i += 1
            elif c == ")" and depth:
                depth -= 1
            elif c == '"':
                quote = None if quote == '"' else ('"' if not depth else quote)
            elif c == "'" and quote is None:
                quote = "'"
            elif quote is None and depth == 0 and (c in ";|" or line.startswith("&&", i) or c == ")"):
                end = i
                break
            i += 1
        out.append((m.group(1), line[m.end():end], line[end:end + 2], before))
    return out


def tainted_names(text):
    """Variables that hold a node-derived value: assigned from a node channel, or from such a variable."""
    assigns = []
    for _, line, _ in logical_lines(text):
        for m in re.finditer(r"(?:^|[\s;(])(?:local\s+)?(\w+)=(\"\$\(.*|\$\(.*|\"[^\"]*\"|\S*)", line):
            assigns.append((m.group(1), m.group(2)))
    names = set()
    while True:
        new = {v for v, rhs in assigns if v not in names and (
            re.search(r"(?<![\w$-])(?:%s)(?![\w-])" % "|".join(TAINT_SOURCES), rhs)
            or any(re.search(r"\$\{?#?%s\b" % re.escape(n), rhs) for n in names))}
        if not new:
            return names
        names |= new


def taint_findings(text, names):
    """Sink commands whose arguments name a node-derived variable other than through an allowed helper."""
    bad, checked = [], 0
    helper = r"\$\((?:%s)(?: \"\$\{?\w+\}?\")+\)" % "|".join(sorted(ALLOWED))
    for n, line, func in logical_lines(text):
        if func in ALLOWED or re.match(r"^\s*(?:ok|no|die)\(\) \{", line):
            continue
        for cmd, args, after, before in _segments(line, "|".join(SINKS)):
            if cmd in ("echo", "printf"):
                # Output into a pipe, a capture or a file is not the terminal.
                if after.startswith("|") and not after.startswith("||"):
                    continue
                if before.count("$(") > before.count(")"):
                    continue
                if re.search(r"(?<![0-9&])>\s*(?!&)\S", args):
                    continue
            checked += 1
            rest = re.sub(helper, "", args)
            hit = [v for v in names if re.search(r"\$\{?[#!]?%s\b" % re.escape(v), rest)]
            if hit:
                bad.append("%d:%s:%s" % (n, cmd, ",".join(sorted(hit))))
    return bad, checked


def closed_world_taint(fs):
    """Source-level closed world: no node-derived variable reaches ok/no/die/echo/printf except through
    reply_status, reply_len or reply_version."""
    names = tainted_names(fs)
    expect = {"code", "versions", "api_key", "resp", "qcode", "qjson", "QID", "landed", "sresp", "scode", "sjson",
              "SID", "lvl", "pg_ver", "age_ver", "vec_ver"}
    probe("V1 the taint scan finds every node-derived variable (not vacuous)", expect <= names, str(sorted(expect - names)))
    bad, checked = taint_findings(fs, names)
    probe("V1 no node-derived variable reaches a terminal line except through reply_status/reply_len/reply_version",
          not bad, " ".join(bad[:8]))
    probe("V1 the taint scan checks the terminal lines (not vacuous)", checked >= 60, str(checked))
    wrap = lambda body: fs + "\nprobe_fn() {\n%s\n}\n" % body
    for label, body in (("a raw reply in a failure line", 'no "x $qjson"'),
                        ("an excerpt helper outside the allow-list", 'no "x $(safe_excerpt "$qjson")"'),
                        ("an echo of the attest level", 'echo "$lvl"'),
                        ("a printf of the memory id", "printf '%s\\n' \"$QID\""),
                        ("an echo inside a failure line", 'no "x $(echo "$sjson")"'),
                        ("a length expansion in a PASS line", 'ok "x ${#resp}"'),
                        ("the key in a refusal", 'die "bad key $api_key"'),
                        ("a helper and then the raw status", 'no "x $(reply_len "$qjson") $qcode"'),
                        ("a helper wrapping a pipeline", 'no "x $(reply_len "$qjson" | cat; echo "$qjson")"'),
                        ("a variable derived from a reply", 'tok="${versions%% *}"\nno "x $tok"'),
                        ("an echo to stderr", 'echo "$code" >&2')):
        b2, _ = taint_findings(wrap(body), tainted_names(wrap(body)))
        probe("V1 closed-world negative control is flagged: %s" % label, len(b2) > len(bad), str(b2[len(bad):][:2]))
    for label, body in (("helpers only", 'no "x $(reply_status "$qcode") ($(reply_len "$qjson"))"'),
                        ("a reply piped to grep", "echo \"$versions\" | grep -qx 'age=1.8.0'"),
                        ("a reply captured through sed", "age_ver=\"$(printf '%s\\n' \"$versions\" | sed -n 's/^age=//p')\"")):
        b2, _ = taint_findings(wrap(body), tainted_names(wrap(body)))
        probe("V1 closed-world control is accepted: %s" % label, len(b2) == len(bad), str(b2[len(bad):][:2]))


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
              "scode=500\nsjson='{}'\nSID=''\n%s\necho done\n" % (plain_id_def(fs) + "\n" + reply_defs(fs), snip))
        r = run_bash(sc, d)
        probe("#4957 a failed signed write with no id is one failure line, with srefused initialised under set -u",
              0 <= i < j and r.returncode == 0 and "done" in r.stdout and r.stdout.count("NO ") == 1 and "'500'" in r.stdout
              and "OK" not in r.stdout and "unbound" not in r.stderr, (r.stdout + r.stderr).strip()[:100])
        # #5104: a rejected write must not be followed by a node-2 PASS. Each site runs whole, readback
        # included, with a node_get that would report success; a failed write is one FAIL and no readback.
        defs = plain_id_def(fs) + "\n" + reply_defs(fs)
        qa = fs.find('  case "$qcode" in')
        qb = fs.find("  # A4 --", qa) if qa >= 0 else -1
        sa = fs.find('      SID=$(echo "$sjson" | jq -r \'.id // empty\' 2>/dev/null)\n')
        sb = fs.find("    fi\n  fi\n  fi # NODE_COUNT", sa) if sa >= 0 else -1
        sa += len('      SID=$(echo "$sjson" | jq -r \'.id // empty\' 2>/dev/null)\n') if sa >= 0 else 0
        sites = (("quorum", fs[qa:qb] if 0 <= qa < qb else "", "qcode", "qjson", "QID", '{"id":"abc"}'),
                 ("signed", fs[sa:sb] if 0 <= sa < sb else "", "scode", "sjson", "SID", '{"id":"abc"}'))
        # #5146: the other 2xx codes too. The quorum site accepts 202 (mesh-accepted) and must read it
        # back; the signed site accepts only 201. A 200 or 204 is not an accepted write at either site.
        for name, snip, cv, jv, idv, body in sites:
            for code, want_ok, want_called, label in (("500", 0, 0, "a 500"), ("403", 0, 0, "a 403"),
                                                      ("201", 2, 1, "a 201 (control)"),
                                                      ("202", 2 if name == "quorum" else 0, 1 if name == "quorum" else 0,
                                                       "a 202 (mesh-accepted control)" if name == "quorum" else "a 202"),
                                                      ("200", 0, 0, "a 200"), ("204", 0, 0, "a 204")):
                sc = ("set -u\n%s\nok() { echo \"OK $*\"; }\nno() { echo \"NO $*\"; }\n"
                      "node_get() { : > %s; echo '{\"id\":\"abc\",\"metadata\":{\"attest_level\":\"agent_attested\"}}'; }\n"
                      "sleep() { :; }\n%s='%s'\n%s='%s'\n%s='abc'\nQID=${QID:-}\nSID=${SID:-}\n%s\n"
                      % (defs, d / "called", cv, code, jv, body, idv, snip))
                (d / "called").unlink() if (d / "called").exists() else None
                r = run_bash(sc, d)
                oks = sum(1 for l in r.stdout.splitlines() if l.startswith("OK"))
                nos = sum(1 for l in r.stdout.splitlines() if l.startswith("NO"))
                called = 1 if (d / "called").exists() else 0
                want_no = 0 if want_ok else 1
                probe("#5104 %s write with %s: %d FAIL, %d PASS, readback %s" % (name, label, want_no, want_ok, "runs" if want_called else "skipped"),
                      bool(snip) and r.returncode == 0 and nos == want_no and oks == want_ok and (called > 0) == bool(want_called),
                      "rc=%s no=%d ok=%d called=%d %s" % (r.returncode, nos, oks, called, r.stderr.strip()[:60]))
        # #5145: a write the node accepts (201 or 202) but answers with no memory id cannot be read back at
        # node 2, so it is one FAIL that says so, never a PASS that silently skips the replication check.
        for name, snip, cv, jv, idv, _ in sites:
            for code in ("201", "202"):
                sc = ("set -u\n%s\nok() { echo \"OK $*\"; }\nno() { echo \"NO $*\"; }\n"
                      "node_get() { : > %s; echo '{\"id\":\"abc\",\"metadata\":{\"attest_level\":\"agent_attested\"}}'; }\n"
                      "sleep() { :; }\n%s='%s'\n%s='{}'\nQID=''\nSID=''\n%s\n"
                      % (defs, d / "called", cv, code, jv, snip))
                (d / "called").unlink() if (d / "called").exists() else None
                r = run_bash(sc, d)
                oks = sum(1 for l in r.stdout.splitlines() if l.startswith("OK"))
                nos = sum(1 for l in r.stdout.splitlines() if l.startswith("NO"))
                called = 1 if (d / "called").exists() else 0
                probe("#5145 %s write accepted with %s and no memory id: 1 FAIL, 0 PASS, no readback" % (name, code),
                      bool(snip) and r.returncode == 0 and nos == 1 and oks == 0 and called == 0,
                      "rc=%s no=%d ok=%d called=%d %s" % (r.returncode, nos, oks, called, r.stderr.strip()[:60]))
        # #5170: the memory id is node-supplied and plain_id admits a 64-hex value, so a PASS or FAIL line
        # that names the id would print a key-shaped value. Read back found and not found, both sites.
        for name, snip, cv, jv, idv, _ in sites:
            for found in (True, False):
                reply = "echo '{\"id\":\"%s\",\"metadata\":{\"attest_level\":\"agent_attested\"}}'" % SECRET if found else ":"
                sc = ("set -u\n%s\nok() { echo \"OK $*\"; }\nno() { echo \"NO $*\"; }\nnode_get() { %s; }\n"
                      "sleep() { :; }\n%s='201'\n%s='{\"id\":\"%s\"}'\n%s='%s'\nQID=${QID:-}\nSID=${SID:-}\n%s\n"
                      % (defs, reply, cv, jv, SECRET, idv, SECRET, snip))
                r = run_bash(sc, d)
                probe("#5170 %s write with a key-shaped memory id (read back %s): the id is on no line" % (name, "found" if found else "missing"),
                      bool(snip) and r.returncode == 0 and ("OK" in r.stdout or "NO" in r.stdout)
                      and SECRET not in r.stdout and SECRET not in r.stderr, r.stdout.strip()[:100])


CHANNELS = ("on_node", "node_sh", "node_get", "node_post", "scp", "ssh", "curl", "lg_curl")
# Functions whose job is to hand a node's stdout to their caller: inside them only stderr must be closed.
CHANNEL_WRAPPERS = ("node_get", "node_post")
# Function definitions that ARE a channel (their body is the ssh/curl call itself).
CHANNEL_DEFS = re.compile(r"^\s*(on_node|node_sh|lg_curl)\(\) \{")


def logical_lines(text):
    """(first line number, joined text, enclosing function) per logical line, outside heredoc bodies and comments."""
    out, buf, start, func, heredoc = [], "", 0, "", None
    for n, raw in enumerate(text.splitlines(), 1):
        if heredoc is not None:
            if raw == heredoc:
                heredoc = None
            continue
        if not buf and raw.lstrip().startswith("#"):
            continue
        m = re.match(r"^(\w+)\(\) \{", raw)
        if m:
            func = m.group(1)
        if not buf:
            start = n
        buf += raw[:-1] + " " if raw.endswith("\\") else raw
        if raw.endswith("\\"):
            continue
        h = re.search(r"<<-?\s*'?(\w+)'?", buf)
        if h:
            heredoc = h.group(1)
        out.append((start, buf, func))
        if raw.startswith("}"):
            func = ""
        buf = ""
    return out


def strip_messages(line):
    """Drop the text of die/echo/ok/no messages, which may name a command without running it."""
    return re.sub(r'\b(?:die|echo|ok|no)\s+"(?:[^"\\$]|\\.|\$(?!\()|\$\((?:[^()]|\([^()]*\))*\))*"', "MSG", line)


def node_stream_findings(text):
    """#5171: every node-channel call closes stderr and captures or discards stdout (wrappers: stderr only)."""
    bad = []
    for n, line, func in logical_lines(text):
        if CHANNEL_DEFS.match(line) or re.match(r"^\s*\w+\(\) \{\s*$", line):
            continue
        code = strip_messages(line)
        for m in re.finditer(r"(?<![\w$/.-])(%s)(?![\w-])" % "|".join(CHANNELS), code):
            before = code[:m.start()]
            # A wrapper closes its own stderr (its body is checked like any other line).
            err_ok = (m.group(1) in CHANNEL_WRAPPERS
                      or re.search(r"2>\s*/dev/null|2>&1|&>\s*/dev/null", code) is not None)
            out_ok = (before.count("$(") > before.count(")")
                      or re.search(r"(?<![0-9&])>\s*/dev/null|>&9|-o /dev/null", code) is not None
                      or func in CHANNEL_WRAPPERS)
            if not (err_ok and out_ok):
                bad.append("%d:%s:%s" % (n, m.group(1), "stderr" if not err_ok else "stdout"))
    return bad


def node_streams_5171():
    """#5171: no node-channel call streams node output to the operator terminal."""
    fs = FED.read_text()
    bad = node_stream_findings(fs)
    probe("#5171 every node-channel call in federate.sh closes stderr and captures or discards stdout", not bad, " ".join(bad[:12]))
    seen = sum(1 for _, l, _ in logical_lines(fs) for _ in re.finditer(r"(?<![\w$/.-])(?:%s)(?![\w-])" % "|".join(CHANNELS), strip_messages(l)))
    probe("#5171 the node-stream check sees the channel calls (not vacuous)", seen >= 30, str(seen))
    probe("#5171 no node log is printed (the MESH READY timeout names the command instead)", not re.search(r"(?:on_node|node_sh|ssh)[^\n]*tail -30", fs.replace("echo \"[federate] node $n federation log: ssh", ""))
          and "/var/log/ai-memory-federation.log" in fs)
    # Negative controls: each of these streams node output and must be flagged.
    for label, snippet in (("an on_node with no redirect", 'until on_node "$host" "test -f x"; do sleep 1; done'),
                           ("an on_node with stdout to the terminal's stderr", 'on_node "$host" "tail -30 /var/log/x" >&2 || true'),
                           ("a node_sh heredoc with stdout captured but stderr open", 'v="$(node_sh "$i" <<\'EOS\'\npsql\nEOS\n)"'),
                           ("an scp with no redirect", 'scp $SSH_OPTS -q a "${SSH_USER}@${host}:/x" || die "scp failed"'),
                           ("a curl writing the body to stdout", 'curl -sS https://x 2>/dev/null'),
                           ("an ssh in a pipeline", 'ssh h cat /x | head -1')):
        probe("#5171 negative control is flagged: %s" % label, bool(node_stream_findings(snippet + "\n")))
    for label, snippet in (("a captured, stderr-closed node_sh", 'v="$(node_sh "$i" <<\'EOS\' 2>/dev/null\npsql\nEOS\n)"'),
                           ("an on_node with both streams closed", 'on_node "$h" "touch x" >/dev/null 2>&1 || die "scp: could not"')):
        probe("#5171 control is accepted: %s" % label, not node_stream_findings(snippet + "\n"), str(node_stream_findings(snippet + "\n")))


def version_block(fs):
    """The verify loop that reads the certified data-tier versions from each node, or empty."""
    a = fs.find("  # Certified data-tier pins, asserted from the provisioned hosts.\n")
    b = fs.find("  # These two assertions intentionally originate on f2", a) if a >= 0 else -1
    return fs[a:b] if 0 <= a < b else ""


def run_versions(fs, defs, reply, d):
    """Run the version loop for one node whose psql reply is reply; return the CompletedProcess."""
    (d / "versions.reply").write_bytes(reply.encode("utf-8", "surrogateescape"))
    sc = ("set -u\n%s\nok() { echo \"OK $*\"; }\nno() { echo \"NO $*\"; }\nNODE_COUNT=1\napi_key=''\n"
          "node_sh() { cat %s; }\n%s\n" % (defs, d / "versions.reply", version_block(fs)))
    return run_bash(sc, d)


def pg_version_5172():
    """#5172: PostgreSQL passes only when the server_version token is exactly 18.6."""
    fs = FED.read_text()
    defs = reply_defs(fs)
    tail = "\nage=1.8.0\nvector=0.8.6\n"
    with tempfile.TemporaryDirectory(dir=str(ROOT / ".local-runs")) as t:
        d = pathlib.Path(t)
        for first, want in (("18.6", True), ("18.6 (Debian 18.6-1.pgdg)", True), ("18.60", False),
                            ("18.61 (Debian)", False), ("18.6.1", False), ("18.6beta", False), ("17.2", False)):
            r = run_versions(fs, defs, first + tail, d)
            pg = [l for l in r.stdout.splitlines() if "PostgreSQL" in l]
            probe("#5172 server_version %r gives %s" % (first, "PASS" if want else "FAIL"), bool(version_block(fs)) and len(pg) == 1
                  and pg[0].startswith("OK" if want else "NO"), "%s" % pg)
        r = run_versions(fs, defs, "17.2\n18.6\n" + tail, d)
        pg = [l for l in r.stdout.splitlines() if "PostgreSQL" in l]
        probe("#5172 18.6 on a line after server_version does not pass", len(pg) == 1 and pg[0].startswith("NO"), "%s" % pg)


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
    pg_version_5172()
    node_streams_5171()
    f3_static_pins()
    print("RESULT: %s (%d failed)" % ("FAIL" if FAILS else "PASS", len(FAILS)))
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
