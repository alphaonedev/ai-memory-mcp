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
import functools
import re
import signal
import shutil
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


def mint_block():
    """The provision.sh role-password rotation statements (from the URL read to the placeholder refusal), with the
    Terraform escape $${ turned into the shell text ${ and the store-url path left for the caller to replace."""
    tpl = TPL.read_text()
    m = re.search(r"^[ ]*URL=\"\$\(LC_ALL=C sed -n .*?^[ ]*echo \"placeholder db password still in /etc/ai-memory/store-url\"; exit 1\n[ ]*fi\n", tpl, re.S | re.M)
    return None if not m else m.group(0).replace("$${", "${")


PLACEHOLDER_URL = "postgres://aimemory:CHANGEME@localhost/aimemory?sslmode=verify-full\n"
ROTATED = "postgres://aimemory:abc123@localhost/aimemory?sslmode=verify-full\n"
# #5640: one message per refusal cause.
MSG_LINES = "store-url must hold exactly one non-empty line"
MSG_SHAPE = "store-url line is not one aimemory URL of printable ASCII characters with an unreserved password"
MSG_PLACEHOLDER = "placeholder db password still in"


def f4_sed():
    """#5428: the rotation reads the store-url with fixed sed -n, writes it with the bash printf builtin, and the
    new secret is on no argv. CHANGEME is replaced, a rotated file is unchanged, an empty or non-URL file is minted."""
    block = mint_block()
    probe("F4 mint block present", bool(block))
    if not block:
        return
    probe("F4 no grep on the store-url", "grep" not in block)
    # #5522: the comment above the block states the rule the code applies.
    probe("F4 the comment names the replaced files: no postgres://aimemory line",
          "no postgres://aimemory:...@ line" in TPL.read_text() and "holds no URL" not in TPL.read_text())
    probe("F4 no sed -i or script on stdin", not re.search(r"sed\s+(-\S*i|-f)", block))
    probe("#5640 the comment states that the daemon reads the whole file as one URL",
          "the daemon trims the file and reads all the rest as one URL" in block and "(#5640)" in block, "")
    cases = [
        ("CHANGEME is replaced", "postgres://aimemory:CHANGEME@localhost/aimemory?sslmode=verify-full\n", "mint"),
        ("rotated file is unchanged", "postgres://aimemory:abc123@localhost/aimemory?sslmode=verify-full\n", "keep"),
        ("empty file is minted", "", "fresh"),
        ("non-URL file is minted", "garbage\n", "fresh"),
        # The refusal is reachable only when the mint yields no usable value: a stub that prints the placeholder
        # or nothing must make the block exit 1 and leave no running node with a placeholder password.
        ("a mint that yields the placeholder is refused", "garbage\n", "refuse:CHANGEME"),
        ("a mint that yields nothing is refused", "garbage\n", "refuse::" + MSG_SHAPE),
        # #5522: any file without a postgres://aimemory:...@ line is replaced, whatever else it holds.
        ("another scheme is minted", "postgresql://aimemory:keepme@db/aimemory\n", "fresh"),
        ("another user is minted", "postgres://admin:keepme@db/aimemory\n", "fresh"),
        # #5521: a file with more than one URL line is undecidable, so it is refused, never kept or half-minted.
        ("two placeholder lines are refused", PLACEHOLDER_URL + PLACEHOLDER_URL, "refuse:" + SECRET + ":" + MSG_LINES),
        ("a placeholder line after a rotated line is refused", "postgres://aimemory:abc123@h/x\n" + PLACEHOLDER_URL,
         "refuse:" + SECRET + ":" + MSG_LINES),
        ("two rotated lines are refused", "postgres://aimemory:abc123@h/x\npostgres://aimemory:def456@h/x\n",
         "refuse:" + SECRET + ":" + MSG_LINES),
        # #5640: the daemon trims the file and reads the rest as one URL, so the check reads every line, not only the
        # URL lines, and each refusal names its cause.
        ("a second postgresql:// line is refused", ROTATED + "postgresql://aimemory:def456@h/x\n", "refuse:" + SECRET + ":" + MSG_LINES),
        ("a trailing garbage line is refused", ROTATED + "garbage\n", "refuse:" + SECRET + ":" + MSG_LINES),
        ("a leading garbage line is refused", "garbage\n" + ROTATED, "refuse:" + SECRET + ":" + MSG_LINES),
        ("a line of spaces after the URL is refused", ROTATED + "   \n", "refuse:" + SECRET + ":" + MSG_LINES),
        ("a CR line end is refused", ROTATED.replace("\n", "\r\n"), "refuse:" + SECRET + ":" + MSG_SHAPE),
        ("a CR line end on the placeholder is refused", PLACEHOLDER_URL.replace("\n", "\r\n"), "refuse:" + SECRET + ":" + MSG_SHAPE),
        ("CR line ends on two lines are refused", (ROTATED + "x\n").replace("\n", "\r\n"), "refuse:" + SECRET + ":" + MSG_LINES),
        ("a tab inside the URL is refused", "postgres://aimemory:abc123@h/x\ty\n", "refuse:" + SECRET + ":" + MSG_SHAPE),
        ("an escape byte inside the URL is refused", "postgres://aimemory:abc123@h/x\x1by\n", "refuse:" + SECRET + ":" + MSG_SHAPE),
        ("a quote in the password is refused", "postgres://aimemory:ab'c@h/x\n", "refuse:" + SECRET + ":" + MSG_SHAPE),
        ("a percent-escaped password is kept", "postgres://aimemory:a%2Fb.c_d~e-f@h/x?sslmode=verify-full\n", "keep"),
        ("a space inside the URL is refused", "postgres://aimemory:abc123@h/x y\n", "refuse:" + SECRET + ":" + MSG_SHAPE),
        ("an empty password is minted", "postgres://aimemory:@h/x\n", "fresh"),
        ("leading and trailing blank lines keep a rotated file", "\n\n" + ROTATED + "\n", "keep"),
        ("a rotated file with no final newline is kept", ROTATED[:-1], "keep"),
        ("a trailing line of non-UTF-8 bytes is refused", ROTATED + "\udcff\udcfe\n", "refuse:" + SECRET + ":" + MSG_LINES),
        ("a URL line with a non-UTF-8 byte is refused", ROTATED.replace("localhost", "local\udcffhost"), "refuse:" + SECRET + ":" + MSG_SHAPE),
        ("a line that is only a CR after the URL is refused", ROTATED + "\r\n", "refuse:" + SECRET + ":" + MSG_LINES),
        ("blank lines around the placeholder are minted", "\n" + PLACEHOLDER_URL + "\n", "mint"),
    ]
    # #5640: every case runs in the C locale too, where a high byte is a character and the shape check must still
    # refuse it.
    # #5640: the checks after the mint refuse on their own, whatever the mint left: an empty file, a file of blank
    # lines and another user are each refused with the message that names the cause, and a rotated file passes.
    checks = block[block.find("printf -v NL"):] if "printf -v NL" in block else ""
    probe("#5640 the checks after the mint are found", bool(checks))
    for label, start, rc, why in (("an empty file", "", 1, MSG_LINES), ("a file of blank lines", "\n\n", 1, MSG_LINES),
                                  ("another user", "postgres://admin:keepme@db/aimemory\n", 1, MSG_SHAPE),
                                  ("a rotated file", ROTATED, 0, "")):
        with tempfile.TemporaryDirectory(dir=str(ROOT / ".local-runs")) as t:
            f = pathlib.Path(t) / "store-url"
            f.write_text(start)
            r = run_bash(checks.replace("/etc/ai-memory/store-url", str(f)), pathlib.Path(t))
            probe("#5640 the checks alone on %s: rc %d %s" % (label, rc, why or "and no message"),
                  r.returncode == rc and r.stdout.startswith(why) and r.stdout.count("\n") == rc,
                  "rc=%d %r" % (r.returncode, r.stdout[:60]))
    for label, start, want, lc in [c + (l,) for c in cases for l in ("", "C")]:
        label = label + (" [LC_ALL=C]" if lc else "")
        with tempfile.TemporaryDirectory(dir=str(ROOT / ".local-runs")) as t:
            d = pathlib.Path(t)
            (d / "sed").write_text('#!/bin/bash\nprintf "%s\\n" "$@" >> "$LOGDIR/argv.log"\nexec /usr/bin/sed "$@"\n')
            (d / "sed").chmod(0o755)
            mint, _, why = (want[7:] if want.startswith("refuse:") else SECRET).partition(":")
            (d / "openssl").write_text('#!/bin/bash\nprintf "%s\\n" "$@" >> "$LOGDIR/argv.log"\nprintf "%s\\n" "' + mint + '"\n')
            (d / "openssl").chmod(0o755)
            f = d / "store-url"
            f.write_bytes(start.encode("utf-8", "surrogateescape"))
            r = run_bash(block.replace("/etc/ai-memory/store-url", str(f)), d, {"LC_ALL": lc} if lc else None)
            got = f.read_bytes().decode("utf-8", "surrogateescape")
            argv = (d / "argv.log").read_text() if (d / "argv.log").exists() else ""
            if want.startswith("refuse:"):
                why = why or MSG_PLACEHOLDER
                probe("F4 " + label + ": rc 1 with the message that names the cause",
                      r.returncode == 1 and r.stdout.startswith(why) and r.stdout.count("\n") == 1,
                      "rc=%d %r" % (r.returncode, r.stdout[:60]))
                probe("F4 " + label + ": secret on no external argv", SECRET not in argv)
                continue
            probe("F4 " + label + ": rc 0", r.returncode == 0, r.stderr[:80])
            if want == "keep":
                probe("F4 " + label + ": file bytes unchanged", got == start, repr(got[:60]))
            else:
                probe("F4 " + label + ": minted value in a URL, no placeholder", SECRET in got and "CHANGEME" not in got
                      and got.startswith("postgres://aimemory:" + SECRET + "@localhost/"), repr(got[:60]))
            probe("F4 " + label + ": secret on no external argv", SECRET not in argv)


def utf8_locales():
    """The UTF-8 locales the store-url locale cases run under: C.UTF-8 always (a missing one is a failure, not a
    skip), en_US.UTF-8 when it is installed."""
    r = subprocess.run(["locale", "-a"], capture_output=True, text=True)
    have = {l.strip().lower().replace("-", "") for l in r.stdout.splitlines()}
    return ["C.UTF-8"] + (["en_US.UTF-8"] if "en_us.utf8" in have else [])


def store_url_shape_locale_5764():
    """#5764: the store-url shape check refuses a URL with a byte outside printable ASCII in every locale. Under a
    UTF-8 locale the [[:alnum:]] and [[:graph:]] classes match multibyte letters and a no-break space, so the sed
    runs under LC_ALL=C."""
    tpl = TPL.read_text()
    probe("#5764 the shape sed runs under LC_ALL=C",
          re.search(r"^ +SHAPED=\"\$\(LC_ALL=C sed -n 's#\^postgres\[:\]//aimemory:", tpl, re.M) is not None, "")
    probe("#5764 the comment states ASCII and the C locale, and no any-locale claim",
          "printable ASCII characters only" in tpl and "The shape sed runs under LC_ALL=C" in tpl
          and "in\n      # any locale" not in tpl, "")
    block = mint_block()
    probe("#5764 mint block present", bool(block))
    if not block:
        return
    locales = utf8_locales()
    for lc in locales:
        r = subprocess.run(["sed", "-n", "s#^[[:alnum:]]x[[:graph:]]$#y#p"], input="\u00e9x\u00a0\n".encode("utf-8"),
                           capture_output=True, env={"PATH": os.environ["PATH"], "LC_ALL": lc})
        probe("#5764 %s makes the classes match a multibyte letter and a no-break space (the case discriminates)" % lc,
              r.stdout == b"y\n", repr(r.stdout))
    for lc in locales + ["C", "POSIX"]:
        for label, start, rc in (("an e-acute in the password", "postgres://aimemory:ab\u00e9@localhost/x\n", 1),
                                 ("an e-acute in the host", "postgres://aimemory:abc123@loc\u00e9/x\n", 1),
                                 ("a no-break space in the host", "postgres://aimemory:abc123@loc\u00a0x/x\n", 1),
                                 ("a rotated ASCII URL", ROTATED, 0)):
            with tempfile.TemporaryDirectory(dir=str(ROOT / ".local-runs")) as d:
                f = pathlib.Path(d) / "store-url"
                f.write_bytes(start.encode("utf-8"))
                r = run_bash(block.replace("/etc/ai-memory/store-url", str(f)), pathlib.Path(d), {"LC_ALL": lc})
                kept = f.read_bytes() == start.encode("utf-8")
                if rc:
                    probe("#5764 %s is refused with the shape message under %s, file unchanged" % (label, lc),
                          r.returncode == 1 and r.stdout.startswith(MSG_SHAPE) and r.stdout.count("\n") == 1 and kept,
                          "rc=%d %r" % (r.returncode, r.stdout[:70]))
                else:
                    probe("#5764 %s is kept under %s" % (label, lc), r.returncode == 0 and kept and not r.stdout,
                          "rc=%d %r" % (r.returncode, r.stdout[:70]))



def store_url_premint_locale_5807():
    """#5807: every sed that reads the store-url runs under LC_ALL=C, so the mint decision is the same in every
    locale. Under a UTF-8 locale [^@]* and .* stop at a byte that is not valid UTF-8, so the password read came out
    empty and a store-url whose password held such a byte was silently replaced by a fresh mint."""
    tpl = TPL.read_text()
    reads = re.findall(r"^.*\bsed\b.*/etc/ai-memory/store-url.*$", tpl, re.M)
    probe("#5807 the template reads the store-url with sed at 7 sites", len(reads) == 7, repr(len(reads)))
    bare = [l.strip() for l in reads if not re.search(r"\"\$\(LC_ALL=C sed -n '", l)]
    probe("#5807 every sed that reads the store-url runs under LC_ALL=C", not bare, repr(bare[:2]))
    probe("#5807 the comment states that the file is read under LC_ALL=C in every locale",
          "Every such sed runs under LC_ALL=C, so a class or a dot matches one byte\n      # whatever the node's locale"
          " (#5807)" in tpl, "")
    block = mint_block()
    probe("#5807 mint block present", bool(block))
    if not block:
        return
    locales = utf8_locales()
    for lc in locales:
        r = subprocess.run(["sed", "-n", "s#^p:\\([^@]*\\)@.*#\\1#p"], input=b"p:ab\xff@h\n", capture_output=True,
                           env={"PATH": os.environ["PATH"], "LC_ALL": lc})
        probe("#5807 %s makes [^@]* stop at an invalid byte (the case discriminates)" % lc, r.stdout == b"", repr(r.stdout))
    bad_pw = b"postgres://aimemory:ab\xff@localhost/x\n"
    bad_host = b"postgres://aimemory:CHANGEME@loc\xffx/x\n"
    for lc in locales + ["C", "POSIX"]:
        for label, start, want in (("an invalid byte in the password", bad_pw, bad_pw),
                                   ("a placeholder with an invalid byte in the host", bad_host,
                                    bad_host.replace(b"CHANGEME", SECRET.encode())),
                                   ("a rotated ASCII URL", ROTATED.encode(), None)):
            with tempfile.TemporaryDirectory(dir=str(ROOT / ".local-runs")) as t:
                d = pathlib.Path(t)
                (d / "openssl").write_text('#!/bin/bash\nprintf "%s\\n" "' + SECRET + '"\n')
                (d / "openssl").chmod(0o755)
                f = d / "store-url"
                f.write_bytes(start)
                r = run_bash(block.replace("/etc/ai-memory/store-url", str(f)), d, {"LC_ALL": lc})
                got = f.read_bytes()
                if want is None:
                    probe("#5807 %s is kept under %s" % (label, lc), r.returncode == 0 and got == start and not r.stdout,
                          "rc=%d %r" % (r.returncode, r.stdout[:70]))
                    continue
                probe("#5807 %s is refused with the shape message under %s, not replaced by a fresh mint" % (label, lc),
                      r.returncode == 1 and r.stdout.startswith(MSG_SHAPE) and r.stdout.count("\n") == 1 and got == want,
                      "rc=%d %r %r" % (r.returncode, r.stdout[:70], got[:60]))


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
        # #5239: the stub sleeps in the background and waits for it. With a foreground sleep, a
        # process-group SIGINT that lands in the child bash forks for sleep, before it execs, is taken by
        # that child, and sleep then runs its full 30 s; for SIGINT bash waits for its foreground child and
        # carries on when the child did not die of it, so the run outlived the 6 s wait. The wait builtin
        # is interrupted by the signal itself, whatever the fork timing. The leftover sleep is killed with
        # the process group. DO_HIVE_P2_SIGNAL_REPEAT=N runs each signal N times.
        slow = 'on_node() { printf "%%s" %s; : > %s; sleep 30 & wait $!; }\n' % (SECRET[:32], ready)
        rep = os.environ.get("DO_HIVE_P2_SIGNAL_REPEAT", "1")
        repeat = int(rep) if rep.isdigit() and 0 < int(rep) <= 10000 else 0
        if not repeat:
            probe("P2 DO_HIVE_P2_SIGNAL_REPEAT is a count from 1 to 10000", False, rep[:20])
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            bad, hangs, t0 = [], 0, time.monotonic()
            for _ in range(repeat):
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
                try:
                    os.killpg(rp.pid, signal.SIGKILL)  # the background sleep the stub left behind
                except ProcessLookupError:
                    pass
                left = sorted(q.name for q in rd.iterdir())
                hangs += hung
                # #5151: the trap's own exit status (130), not only any non-zero status.
                if not (started and not hung and rc == 130 and not left):
                    bad.append("started=%s rc=%s hung=%s left=%s" % (started, rc, hung, left))
            probe("P2 %s during the key write leaves no temp file and no api-key, and exits 130" % sig.name
                  + (" (%d runs)" % repeat if repeat > 1 else ""), repeat > 0 and not bad,
                  "%d of %d failed, %d hung, %.1fs; first: %s" % (len(bad), repeat, hangs, time.monotonic() - t0,
                                                                  bad[0] if bad else "-"))
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
        # The set is the one the vote names (the key, a URL password, ESC bytes, random bytes) plus the 2xx
        # value; a smaller set makes every byte-identity probe below vacuous.
        hb = [h for _, h in hostile]
        classes = (any(h == SECRET.encode() for h in hb), any(b"x9zQ@" in h for h in hb),
                   any(b"\x1b[" in h and b"PASS" in h for h in hb), any(sum(c >= 128 for c in h) >= 16 for h in hb),
                   any(h.startswith(b"204 ") and SECRET[:16].encode() in h for h in hb))
        probe("V1 the hostile set holds 5 distinct replies: the key, a URL password, ESC bytes, random bytes, a 2xx value",
              len(set(hb)) == 5 and all(classes), repr(classes))
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
        # #5417: a label count other than 1 is one fixed line that prints no version token and no count.
        cnt_age = b"NO node 1 AGE is not 1.8.0 (the labelled row count is not 1)"
        cnt_vec = b"NO node 1 pgvector is not 0.8.6 (the labelled row count is not 1)"
        ok_age, ok_vec = b"OK node 1 AGE 1.8.0", b"OK node 1 pgvector 0.8.6"
        pg = b"NO node 1 PostgreSQL is not 18.6 (got 17.2)"
        for label, reply, want in (
                ("age twice", b"17.2\nage=1.8.0\nage=1.8.0\nvector=0.8.6", [pg, cnt_age, ok_vec]),
                ("age twice, the second empty", b"17.2\nage=1.8.0\nage=\nvector=0.8.6", [pg, cnt_age, ok_vec]),
                ("age twice, both empty", b"17.2\nage=\nage=\nvector=0.8.6", [pg, cnt_age, ok_vec]),
                ("no age row", b"17.2\nvector=0.8.6", [pg, cnt_age, ok_vec]),
                ("no rows at all", b"17.2", [pg, cnt_age, cnt_vec]),
                ("vector twice", b"17.2\nage=1.8.0\nvector=0.8.6\nvector=0.8.6", [pg, ok_age, cnt_vec]),
                ("one empty age label", b"17.2\nage=\nvector=0.8.6", [pg, b"NO node 1 AGE is not 1.8.0 (got 22 bytes)", ok_vec]),
                ("one wrong age version", b"17.2\nage=1.7.0\nvector=0.8.6", [pg, b"NO node 1 AGE is not 1.8.0 (got 1.7.0)", ok_vec]),
                ("one right row each", b"17.2\nage=1.8.0\nvector=0.8.6", [pg, ok_age, ok_vec])):
            r = run_versions_bytes(fs, defs, reply, d, "C.UTF-8")
            probe("#5417 %s: exact lines" % label, bool(vb) and r.stdout.splitlines() == want, repr(r.stdout.splitlines()[:3]))
        # No output line may say a value is not X while showing X as what it got, for any row layout.
        rows = (b"", b"age=1.8.0\n", b"age=1.8.0\nage=1.8.0\n", b"age=\nage=\n", b"age=1.7.0\nage=1.7.0\n", b"age=1.8.0\nage=\n")
        vrows = (b"", b"vector=0.8.6\n", b"vector=0.8.6\nvector=0.8.6\n", b"vector=\nvector=\n", b"vector=0.8.6\nvector=\n")
        bad_lines, seen = [], 0
        for a in rows:
            for v in vrows:
                for first in (b"18.6", b"17.2"):
                    r = run_versions_bytes(fs, defs, first + b"\n" + a + v, d, "C.UTF-8")
                    for ln in r.stdout.splitlines():
                        seen += 1
                        if re.search(rb"is not (\S+) \(got \1\)", ln):
                            bad_lines.append(ln)
        probe("#5417 no line reads: is not X (got X)", bool(vb) and seen > 0 and not bad_lines, repr(bad_lines[:2]))
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


def verify_harness(fs, d, h, xtrace):
    """The whole verify step with every node channel answering h (bytes); (stdout+stderr, wall seconds)."""
    k = fs.find("# --- main")
    (d / "fed-prefix.sh").write_text(fs[:k] if k > 0 else "")
    (d / "signer").write_text("#!/bin/bash\necho sig\n")
    (d / "signer").chmod(0o755)
    (d / "hostile.reply").write_bytes(h)
    sc = ("set -u\nH=\"$(cat %s)\"\nV=\"$H\"$'\\nage='\"$H\"$'\\nvector='\"$H\"\n"
          "source %s\n"
          "NODE_COUNT=2\nPUBLIC_IPS=(h1 h2)\nPEER_URLS=(https://p1:9077 https://p2:9077)\n"
          "node_sh() { local s; s=$(cat); case \"$s\" in *server_version*) printf '%%s' \"$V\" ;; *) printf '%%s' \"$H\" ;; esac; }\n"
          "on_node() { case \"$2\" in *api-key*) printf '%%s\\n' %s ;; *) printf '%%s' \"$H\" ;; esac; }\n"
          "curl() { cat >/dev/null; case \" $* \" in *' -w '*) printf '%%s' \"$H\" ;; *' -o '*) : ;; *) printf '%%s' \"$H\" ;; esac; }\n"
          "node_post() { printf '%%s\\n%%s' \"$H\" \"$H\"; }\nnode_get() { printf '%%s' \"$H\"; }\nsleep() { :; }\n"
          "%sverify; echo \"rc=$?\"\n" % (d / "hostile.reply", d / "fed-prefix.sh", SECRET, "set -x\n" if xtrace else ""))
    (d / "harness.sh").write_text(sc)
    env = dict(os.environ, LC_ALL="C.UTF-8", SIGNER=str(d / "signer"), AUTHOR_KEY_DIR=str(d), OUT_DIR=str(d / "out"))
    t0 = time.monotonic()
    try:
        r = subprocess.run(["bash", str(d / "harness.sh")], capture_output=True, env=env, cwd=str(d), timeout=60,
                           stdin=subprocess.DEVNULL)
        return r.stdout + r.stderr, time.monotonic() - t0
    except subprocess.TimeoutExpired:
        return b"TIMEOUT", time.monotonic() - t0


def verify_cost_5247():
    """#5247: verify parses a large one-line node reply in linear time (no bash suffix/prefix removal on a reply)."""
    fs = FED.read_text()
    with tempfile.TemporaryDirectory(dir=str(ROOT / ".local-runs")) as t:
        d = pathlib.Path(t)
        out, secs = verify_harness(fs, d, b"18.6 " + b"x" * (512 * 1024), False)
        probe("#5247 whole verify on a 512 KiB one-line reply finishes in under 20 s", b"rc=" in out and secs < 20,
              "%.1fs" % secs)
    body = "\n".join(l for l in section(fs, "verify() {", "\n}\n").splitlines() if not l.lstrip().startswith("#"))
    names = sorted(tainted_names(fs) | {"versions", "pg_ver", "age_ver", "vec_ver", "resp", "qjson", "sresp", "sjson", "code", "lvl"})
    strip = re.findall(r"\$\{(?:%s)(?:%%%%|##|%%|#)[^}]" % "|".join(map(re.escape, names)), body)
    probe("#5247 verify does not strip a node reply with ${v%%...}, ${v##...}, ${v%...} or ${v#...}", not strip, str(strip[:4]))


def verify_trace_5237():
    """#5237: no node reply and no key reaches an xtrace log of verify (bash -x)."""
    fs = FED.read_text()
    mark = "7a11" + "fe" * 30  # synthetic 64-hex marker carried by every node reply
    with tempfile.TemporaryDirectory(dir=str(ROOT / ".local-runs")) as t:
        d = pathlib.Path(t)
        for label, h in (("a reply", mark), ("a version reply", "18.6 " + mark)):
            out, _ = verify_harness(fs, d, h.encode(), True)
            why = "reply in trace" if mark.encode() in out else ("key in trace" if SECRET.encode() in out else "")
            probe("#5237 whole verify under bash -x traces no byte of %s and no key" % label,
                  b"rc=" in out and not why, why or ("" if b"rc=" in out else out[-80:]))
    v0 = fs.find("verify() {\n")
    sus = fs.find("{ set +x; } 2>/dev/null", v0)
    first = min(x for x in (fs.find(c, v0) for c in ("on_node", "node_sh", "node_get", "node_post", "curl")) if x >= 0)
    probe("#5237 verify suspends xtrace before its first node read", 0 <= v0 < sus < first, "%d %d %d" % (v0, sus, first))
    head = fs[:fs.find("reply_status() {")]
    probe("#5237 the closed-world comment names the xtrace suspension it relies on",
          "verify suspends xtrace on its first line" in head)
    probe("#5237 no comment says the suspension covers only the rest of verify",
          "suspend -x for the rest of verify" not in fs)


TAINT_SOURCES = ("on_node","node_sh", "node_get", "node_post", "curl", "lg_curl", "ssh", "scp")
SINKS = ("ok", "no", "die", "echo", "printf", "cat", "tee")


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
        out.append((m.group(1), line[m.end():end], line[end:], before))
    return out


def wrapper_names(text):
    """#5360: functions whose body calls a node channel or another such function (fixed point)."""
    wrappers = []
    while True:
        rx = r"(?<![\w$/.-])(?:%s)(?![\w-])" % "|".join(list(TAINT_SOURCES) + wrappers)
        wrap = {f for _, line, f in logical_lines(text) if f and f not in TAINT_SOURCES and f not in wrappers and re.search(rx, line)}
        if not wrap:
            return set(wrappers)
        wrappers += sorted(wrap)


def tainted_names(text):
    """Variables that hold a node-derived value: assigned (=, +=, read, mapfile, readarray, for, printf -v)
    from a node channel or from such a variable (#5236)."""
    assigns = []
    for _, line, _ in logical_lines(text):
        for m in re.finditer(r"(?:^|[\s;(])(?:local\s+)?(\w+)\+?=(\"\$\(.*|\$\(.*|\"[^\"]*\"|\S*)", line):
            assigns.append((m.group(1), m.group(2)))
        for m in re.finditer(r"(?:^|[\s;(])(?:read|mapfile|readarray)((?:\s+(?:-\w+|\w+))+)", line):
            for w in m.group(1).split():
                if not w.startswith("-"):
                    assigns.append((w, line))
        for m in re.finditer(r"(?:^|[\s;(])for\s+(\w+)\s+in\s+([^;]*)", line):
            assigns.append((m.group(1), m.group(2)))
        for m in re.finditer(r"(?:^|[\s;(])printf\s+-v\s+(\w+)\s+(.*)", line):
            assigns.append((m.group(1), m.group(2)))
    # #5360: a function whose body calls a source is a source (to a fixed point), so a wrapper such as
    # node_get is followed without being listed. A wrapper counts only where it is a command word.
    sources, wrappers = list(TAINT_SOURCES), sorted(wrapper_names(text))
    src_rx = r"(?<![\w$-])(?:%s)(?![\w-])" % "|".join(sources)
    wrap_rx = r"(?:^|[\s;(&|{`])(?:%s)(?=[\s;)&|}]|$)" % "|".join(wrappers or ["\\0"])
    names = set()
    while True:
        new = {v for v, rhs in assigns if v not in names and (
            re.search(src_rx, rhs) or re.search(wrap_rx, re.sub(r'"[^"$]*"', '""', rhs))
            or any(re.search(r"\$\{?[#!]?%s\b" % re.escape(n), rhs) for n in names))}
        if not new:
            return names
        names |= new


# #5236, #5412: where does a command's stdout go? Every output redirect (> >> >| &> &>> >&N 1>...) is parsed and
# the LAST one decides, as in bash. Only a plain path (a literal or a "$VAR/..." path) or /dev/null is a file:
# a dup (&N), any other /dev path (stderr, stdout, tty, console, pts, fd, vcs ...), /proc, a target computed by
# $( ), backticks or >( ) is the terminal. #5418, #5523: a target the scan cannot decide is reported, not trusted:
# any target with an expansion or a glob is a file only in the form "$VAR/<segments>" where every segment starts
# with a literal character (not a variable, not ".."), and any ".." segment makes a target the terminal. A target
# held wholly in a variable, a segment held wholly in a variable, and a computed one count as the terminal. The
# VALUE of a variable inside a segment (r$n) and symbolic links are not decided by a static scan.
OUT_REDIRECT = re.compile(r"(?:(?<![0-9&<>])|(?<=[\s;]1))(&>>|&>|>>|>\||>)(?!\()\s*(\"[^\"]*\"|'[^']*'|\S+)")


# #5602: an output target is a file only when the scan proves it. A write, copy or install target is a file when it
# sits under one of these variable roots with a canonical remainder: no empty, . or .. segment, no glob, brace or
# tilde, and no expansion the scan does not model. Every other target, every literal absolute path among them, is
# the terminal; /dev/null is the null device. There is no list of terminal paths to keep complete. #5763: a root
# counts only while root_findings proves its value; otherwise every target is the terminal.
FILE_ROOTS = ("OUT_DIR", "run_dir")
# Markers for the parts of an expanded word whose text the scan models as a class of strings, never as a value:
# a counter ($(( )), seq), a name the script checked against NAME_CHARS, anything (an unmodelled expansion or a
# glob), the X run of a mktemp template, one digit (a date field), and an opaque variable OPEN name CLOSE.
DIGITS, NAME, ANY, ALNUM, ONE_DIGIT, OPEN, CLOSE = "\x01", "\x02", "\x03", "\x04", "\x05", "\x06", "\x07"
NAME_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_:-")
_DIGITS = frozenset("0123456789")
_ALNUM = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")


def _close(s, i):
    """Index just past the $( ... ) or ${ ... } that opens at s[i], quotes and nesting followed."""
    want, opener = (")", "(") if s[i + 1] == "(" else ("}", "{")
    depth, j, quote = 1, i + 2, None
    while j < len(s):
        c = s[j]
        if c == "\\" and quote != "'":
            j += 2
            continue
        if quote:
            if c == quote:
                quote = None
            elif quote == '"' and c == "$" and s[j + 1:j + 2] in ("(", "{"):
                j = _close(s, j)
                continue
            j += 1
            continue
        if c in "'\"":
            quote = c
        elif c == "$" and s[j + 1:j + 2] in ("(", "{"):
            j = _close(s, j)
            continue
        elif c == opener:
            depth += 1
        elif c == want:
            depth -= 1
            if not depth:
                return j + 1
        j += 1
    return len(s)


def shell_words(s):
    """The shell words of `s`: a word ends at unquoted white space or one of ; & | < > ( ); quotes, ${ } and
    $( ) stay whole inside it."""
    out, i = [], 0
    while i < len(s):
        if s[i].isspace() or s[i] in ";&|<>()":
            i += 1
            continue
        st, quote = i, None
        while i < len(s):
            c = s[i]
            if c == "\\" and quote != "'":
                i += 2
                continue
            if quote:
                if c == quote:
                    quote = None
                elif quote == '"' and c == "$" and s[i + 1:i + 2] in ("(", "{"):
                    i = _close(s, i)
                    continue
                i += 1
                continue
            if c in "'\"":
                quote = c
            elif c == "$" and s[i + 1:i + 2] in ("(", "{"):
                i = _close(s, i)
                continue
            elif c.isspace() or c in ";&|<>()":
                break
            i += 1
        out.append(s[st:i])
    return out


def statements(line):
    """The simple commands of a logical line: split at unquoted ; & | and at ( ) that do not open an array value;
    quotes, ${ } and $( ) stay whole."""
    out, cur, i, quote = [], "", 0, None
    while i < len(line):
        c = line[i]
        if c == "\\" and quote != "'":
            cur += line[i:i + 2]
            i += 2
            continue
        if quote:
            if c == quote:
                quote = None
            elif quote == '"' and c == "$" and line[i + 1:i + 2] in ("(", "{"):
                j = _close(line, i)
                cur, i = cur + line[i:j], j
                continue
            cur += c
            i += 1
            continue
        if c in "'\"":
            quote = c
        elif c == "$" and line[i + 1:i + 2] in ("(", "{"):
            j = _close(line, i)
            cur, i = cur + line[i:j], j
            continue
        elif c in ";&|\n" or (c in "()" and line[i - 1:i] != "="):
            if not (c == "&" and (line[i - 1:i] in (">", "<") or line[i + 1:i + 2] == ">")):
                out.append(cur)
                cur, i = "", i + 1
                continue
        cur += c
        i += 1
    out.append(cur)
    return [s for s in out if s.strip()]


def _assignment_map(text):
    """{variable: [value word, ...]} for every assignment in `text`: name=value in command position or after a
    declarator, a declaration with no value (the empty string), and the words of a for loop. None stands for a
    value the scan cannot read (an append, an array). A name=value prefix of a command only sets that command's
    environment, so it is not recorded."""
    vals = {}
    for _, line, _ in logical_lines(text):
        for stage in statements(line):
            words = shell_words(stage)
            k = 0
            while k < len(words) and words[k] in ("if", "then", "elif", "else", "while", "until", "do", "!", "time", "{"):
                k += 1
            if words[k:k + 1] == ["for"] and words[k + 2:k + 3] == ["in"]:
                vals.setdefault(words[k + 1], []).extend(words[k + 3:] or [""])
                continue
            arr = re.match(r"\s*(?:(?:if|then|else|do|!)\s+)*(?:(?:%s)\s+(?:-\w+\s+)*)?(\w+)\+?=\(" % "|".join(DECLARATORS), stage)
            if arr:
                vals.setdefault(arr.group(1), []).append(None)
                continue
            decl = k < len(words) and words[k] in DECLARATORS
            if decl:
                k += 1
                while k < len(words) and words[k].startswith("-"):
                    k += 1
            start = k
            while k < len(words):
                m = re.match(r"(\w+)(\+?)=(\(?)(.*)$", words[k], re.S)
                if m:
                    vals.setdefault(m.group(1), []).append(None if m.group(2) or m.group(3) else m.group(4))
                elif decl and re.fullmatch(r"\w+", words[k]):
                    vals.setdefault(words[k], []).append("")
                elif not decl:
                    break
                k += 1
            if not decl and k < len(words) and k > start:
                for w in words[start:k]:   # a prefix of a command: that command's environment only
                    vals[w.split("=", 1)[0]].pop()
    return vals


_ASSIGN_CACHE = {}


def assigned_values(text, var):
    if text not in _ASSIGN_CACHE:
        if len(_ASSIGN_CACHE) > 8:
            _ASSIGN_CACHE.clear()
        _ASSIGN_CACHE[text] = (_assignment_map(text), _name_checked_arrays(text))
    return _ASSIGN_CACHE[text][0].get(var, [])


def _name_checked_arrays(text):
    """Arrays whose every element the script checks against a subset of NAME_CHARS right after each assignment:
    ARR=( ... ) on one line, then for x in "${ARR[@]}"; do [[ "$x" =~ ^[chars]{1,N}$ ]] || die "..."; done."""
    names = set(re.findall(r"(?m)^\s*(\w+)\+?=\(", text))
    out = set()
    for arr in names:
        loop = (r"[^\n]*\n(?:\s*#[^\n]*\n)*\s*for (\w+) in \"\$\{%s\[@\]\}\"; do\n\s*\[\[ \"\$\1\" =~ \^\[([^\]\n]+)\]\{1,\d+\}\$ \]\]"
                r" \|\| die \"[^\"$`\\]*\"\n\s*done\n") % re.escape(arr)
        sites = [m.start() for m in re.finditer(r"(?m)^\s*%s\+?=" % re.escape(arr), text)]
        good = [m for m in (re.match(r"\s*%s=\(" % re.escape(arr) + loop, text[s:]) for s in sites) if m]
        if sites and len(good) == len(sites) and all(set(m.group(2)) <= NAME_CHARS for m in good) \
                and not re.search(r"%s\[[^\]]*\]\+?=" % re.escape(arr), text):
            out.add(arr)
    return out


def _capture_value(body, text, keep, depth):
    """The expansion of a command substitution the scan models (seq, date +FORMAT, mktemp TEMPLATE), else None."""
    words = shell_words(body)
    if not words:
        return None
    if words[0] == "seq":
        return [DIGITS]
    if words[0] == "date" and words[-1].strip("\"'").startswith("+"):
        fmt = words[-1].strip("\"'")[1:]
        fmt = re.sub(r"%[mdHMS]", ONE_DIGIT * 2, fmt.replace("%Y", ONE_DIGIT * 4))
        return [re.sub(r"%.", ANY, fmt)]
    if words[0] == "mktemp" and not words[-1].startswith("-") and len(words) > 1:
        alts = expand(words[-1], text, keep, depth + 1)
        return None if alts is None else [re.sub(r"X{3,}$", ALNUM, a) for a in alts]
    return None


def expand(word, text, keep=(), depth=0):
    """The alternatives a shell word can expand to, as strings with the markers above. A variable is replaced by
    each value the script assigns it; `keep` names stay OPEN name CLOSE, and so does a variable with no readable
    value (a parameter, the environment, an unmodelled command substitution). ${V:-X} is each value of V and X
    (#5621). Unquoted glob and brace characters are ANY; a leading ~ is opaque.
    Inside a variable's value an unmodelled command substitution makes the whole value None."""
    alts, i, quote = [""], 0, None

    def add(parts):
        nonlocal alts
        alts = list(dict.fromkeys(a + p for a in alts for p in parts))[:64]

    while i < len(word):
        c = word[i]
        if c == "\\" and quote != "'":
            add([word[i + 1:i + 2]])
            i += 2
            continue
        if quote == "'":
            quote = None if c == "'" else quote
            if c != "'":
                add([c])
            i += 1
            continue
        if c == "'" and quote is None:
            quote = "'"
            i += 1
            continue
        if c == '"':
            quote = None if quote == '"' else '"'
            i += 1
            continue
        if c == "$" and word.startswith("$((", i):
            j = _close(word, i)
            add([DIGITS])
            i = j
            continue
        if c == "$" and word[i + 1:i + 2] == "(":
            j = _close(word, i)
            got = _capture_value(word[i + 2:j - 1], text, keep, depth)
            if got is None and depth:
                return None
            add(got if got is not None else [OPEN + "$()" + CLOSE])
            i = j
            continue
        if c == "$" and word[i + 1:i + 2] == "{":
            j = _close(word, i)
            m = re.fullmatch(r"(\w+|[@*#?$!-])(\[[^\]]*\])?(?:(:?[-+=?])(.*))?", word[i + 2:j - 1], re.S)
            if not m or m.group(3) in ("+", ":+", "=", ":=", "?", ":?"):
                got = [ANY]
            elif m.group(3):
                # #5621: ${V:-X} is X when V is unset or empty, else V's value: both alternatives
                dflt = expand(m.group(4), text, keep, depth + 1)
                # inside V's own value (V="${V:-X}") V is an environment override: a stated limit
                val = [] if m.group(1) in _EXPANDING else _var_value(m.group(1), m.group(2), text, keep, depth)
                got = None if dflt is None or val is None else list(dict.fromkeys(val + dflt))
            else:
                got = _var_value(m.group(1), m.group(2), text, keep, depth)
            if got is None:
                return None
            add(got)
            i = j
            continue
        if c == "$" and re.match(r"\$(\w+|[@*#?$!-])", word[i:]):
            m = re.match(r"\$(\w+|[@*#?$!-])", word[i:])
            got = _var_value(m.group(1), None, text, keep, depth)
            if got is None:
                return None
            add(got)
            i += m.end()
            continue
        if quote is None and (c in "*?[]{}" or (c == "~" and i == 0)):
            add([OPEN + "~" + CLOSE] if c == "~" else [ANY])
            i += 1
            continue
        add([c])
        i += 1
    return alts


def _var_value(var, index, text, keep, depth):
    """The alternatives of $var (or ${var[index]}): OPEN var CLOSE when kept or unreadable, NAME for an element of a
    name-checked array, else every assigned value expanded."""
    if var in keep or depth > 6 or not re.fullmatch(r"\w+", var) or var.isdigit():
        return [OPEN + var + CLOSE]
    assigned_values(text, var)
    if index is not None:
        return [NAME] if var in _ASSIGN_CACHE[text][1] else [OPEN + var + CLOSE]
    vals = assigned_values(text, var)
    if not vals or any(v is None for v in vals):
        return [OPEN + var + CLOSE]
    out = []
    _EXPANDING.append(var)
    try:
        for v in vals:
            got = expand(v, text, keep, depth + 1)
            if got is None:
                return [OPEN + var + CLOSE]
            out += got
    finally:
        _EXPANDING.pop()
    return list(dict.fromkeys(out))[:64]


_EXPANDING = []


def seg_atoms(seg):
    """A path segment as a list of (char set or None for any character but /, repeat) atoms."""
    out = []
    for c in re.sub(OPEN + "[^" + CLOSE + "]*" + CLOSE, ANY, seg):
        if c == DIGITS:
            out += [(_DIGITS | {"-"}, False), (_DIGITS, True)]
        elif c == NAME:
            out += [(NAME_CHARS, False), (NAME_CHARS, True)]
        elif c == ALNUM:
            out += [(_ALNUM, False), (_ALNUM, True)]
        elif c == ONE_DIGIT:
            out.append((_DIGITS, False))
        elif c in (ANY, OPEN, CLOSE) or c == "/":
            if not out or out[-1] != (None, True):
                out.append((None, True))
        else:
            out.append((frozenset(c), False))
    return out


def could_equal(a, b):
    """True when some string matches both atom lists a and b (a product walk of the two patterns)."""
    seen, todo = set(), [(0, 0)]
    while todo:
        i, j = todo.pop()
        if (i, j) in seen:
            continue
        seen.add((i, j))
        if i == len(a) and j == len(b):
            return True
        if i < len(a) and a[i][1]:
            todo.append((i + 1, j))
        if j < len(b) and b[j][1]:
            todo.append((i, j + 1))
        if i < len(a) and j < len(b):
            sa, sb = a[i][0], b[j][0]
            if sa is None or sb is None or sa & sb:
                todo.append((i if a[i][1] else i + 1, j if b[j][1] else j + 1))
    return False


# #5763: a root is a root only when the scan proves its value. Each variable a FILE_ROOTS value is built from is
# listed with the one statement that may assign it and the function it sits in ("" is the top level). A listed
# variable is proven when the script names it in that statement exactly once, outside it only to read it or to
# pass the same value to one command (V="$V" cmd), the statement runs unconditionally (no open if, loop, case,
# group, subshell or && || | chain before it in its scope), and every read is after it (a function root: in its
# function). No indirect writer may exist anywhere in the script: eval, source or ., alias, a nameref, a read,
# mapfile, readarray, getopts, printf -v or wait -p with a computed operand, a trap whose action is computed, a
# declarator or unset with a computed name, or a computed command word that is not a path. Any other spelling
# leaves every root unproven: each target under one is then the terminal, and the line is reported.
ROOT_DEFS = (
    ("HERE", "", 'HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"'),
    ("REPO_ROOT", "", 'REPO_ROOT="$(cd "${HERE}/../.." && pwd)"'),
    ("OUT_DIR", "", 'OUT_DIR="${OUT_DIR:-${HERE}/crypto/out}"'),
    ("run_dir", "loadgen", 'run_dir="$REPO_ROOT/.local-runs/do-hive-runs/$(date -u +%Y-%m-%dT%H-%M-%SZ)/loadgen"'),
)
ROOT_INDIRECT = (
    (r"(?<![\w./-])eval(?![\w-])", "eval"), (r"(?<![\w./-])source(?![\w-])", "source"),
    (r"(?:^|[;&|({!]\s*|(?<![\w-])(?:then|do|else|command|builtin|exec)\s+)\.(?=\s)", "source"),
    (r"(?<![\w./-])alias(?![\w-])", "alias"),
    (r"(?<![\w-])(?:declare|local|typeset)\s+(?:-\S+\s+)*-\w*n", "nameref"),
)
# Builtins that assign the variable a name operand names. A literal root name among the operands is a mention of the
# root (reported below); a computed operand (an expansion, a quote or a backslash) may spell one, so it is reported.
NAME_WRITERS = frozenset(("read", "mapfile", "readarray", "getopts"))
REDIRECTION = re.compile(r"\d*(?:<<<|<<-?|&>>|&>|>>|>\||<>|<&|>&|<|>)\s*(?:\"[^\"]*\"|'[^']*'|\S+)")
_COMPOUND_OPEN = frozenset(("if", "for", "while", "until", "case", "select", "{"))
_COMPOUND_CLOSE = frozenset(("fi", "done", "esac", "}"))
_ROOT_CACHE = {}


def _root_reads(name):
    """A read of `name`: $name, ${name}, ${#name}, ${name:-x} and the other expansions that do not assign it."""
    return r"\$%s(?!\w)|\$\{[#!]?%s(?=\}|\[|:(?!=)|[-+?%%#/^,@])" % (name, name)


def _subshell_paren(code):
    """True when `code` holds a ( or ) outside quotes that is not part of $( ), $(( )) or name=( )."""
    i, quote = 0, None
    while i < len(code):
        c = code[i]
        if c == "\\" and quote != "'":
            i += 2
            continue
        if quote:
            if c == quote:
                quote = None
            elif quote == '"' and c == "$" and code[i + 1:i + 2] in ("(", "{"):
                i = _close(code, i)
                continue
            i += 1
            continue
        if c in "'\"":
            quote = c
        elif c == "$" and code[i + 1:i + 2] in ("(", "{"):
            i = _close(code, i)
            continue
        elif c == "(" and code[i - 1:i] == "=":
            i = _close("$" + code[i:], 0) + i - 1
            continue
        elif c in "()":
            return True
        i += 1
    return False


def _depth_change(code):
    """The compound-command depth a logical line opens (if, for, while, until, case, select, {) minus what it
    closes; None when the line holds a case or a subshell paren, which the count does not follow."""
    if _subshell_paren(code):
        return None
    d = 0
    for stmt in statements(code):
        words = shell_words(stmt)
        while words and words[0] in ("!", "time", "then", "do", "else", "elif", "{"):
            if words[0] == "{":
                d += 1
            words = words[1:]
        if not words:
            continue
        if words[0] == "case":
            return None
        if words[0] in _COMPOUND_OPEN:
            d += 1
        elif words[0] in _COMPOUND_CLOSE:
            d -= 1
        d -= sum(1 for w in words[1:] if w == "}")
    return d


def _computed_command(stmt, text):
    """The command word of a simple command when it is computed (holds an expansion) and some value of it is not a
    path: such a word may run a builtin that assigns a variable."""
    if re.match(r"\s*\w+\+?=\(", stmt):
        return None   # an array assignment: its parenthesised words are values, not a command
    words = shell_words(stmt)
    k = 0
    while k < len(words) and (words[k] in ("if", "then", "elif", "else", "while", "until", "do", "!", "time", "{",
                                             "command", "builtin", "exec")
                              or re.match(r"\w+\+?=", words[k])):
        k += 1
    if k >= len(words) or not re.search(r"[$`]", words[k]):
        return None
    alts = expand(words[k], text)
    if not alts or any("/" not in a or a.startswith(OPEN) and "/" not in a.split(CLOSE, 1)[-1] for a in alts):
        return words[k]
    return None


def _name_writer(stmt):
    """The builtin of `stmt` when it assigns a variable named by an operand (read, mapfile, readarray, getopts,
    printf -v, wait -p) and some operand other than a redirection is computed; else None."""
    words = shell_words(REDIRECTION.sub(" ", stmt))
    k = 0
    while k < len(words) and (words[k] in ("if", "then", "elif", "else", "while", "until", "do", "!", "time", "{",
                                             "command", "builtin", "exec")
                              or re.match(r"\w+\+?=", words[k])):
        k += 1
    if k >= len(words):
        return None
    cmd, rest = re.sub(r"[\\'\"]", "", words[k]), words[k + 1:]
    flags = "".join(w[1:] for w in rest if re.fullmatch(r"-\w+", w))
    if cmd in NAME_WRITERS or (cmd == "printf" and "v" in flags) or (cmd == "wait" and "p" in flags):
        if any(re.search(r"[$`'\"\\]", w) for w in rest):
            return cmd
    return None


def _root_pass(name, stmt):
    """True when `stmt` names `name` only as name="$name" before a command word: the same value, passed to that
    command's environment."""
    words = shell_words(stmt)
    k = next((i for i, w in enumerate(words) if w in ('%s="$%s"' % (name, name), "%s=$%s" % (name, name))), -1)
    rest = words[:k] + words[k + 1:]
    return k >= 0 and all(re.match(r"\w+=", w) for w in words[:k]) and k + 1 < len(words) \
        and not re.match(r"\w+\+?=", words[k + 1]) and words[k + 1] not in DECLARATORS | {"unset"} \
        and not re.search(r"(?<!\w)%s(?!\w)" % name, re.sub(_root_reads(name), "", " ".join(rest)))


def root_findings(text):
    """#5763: every line that keeps a FILE_ROOTS value from being proven (see ROOT_DEFS), as line:name:reason."""
    if text in _ROOT_CACHE:
        return _ROOT_CACHE[text]
    bad, lines = [], logical_lines(text)
    for n, line, func in lines:
        code = re.sub(r'"[^"$`]*"', '""', strip_comment(line))
        for rx, label in ROOT_INDIRECT:
            if re.search(rx, code):
                bad.append("%d:roots:%s" % (n, label))
        if re.search(r"(?<![\w-])trap\s+(?!-\s|'[^']*'\s|\"\"\s)", code):
            bad.append("%d:roots:computed trap action" % n)
        for stmt in statements(code):
            words = shell_words(stmt)
            if words and words[0] in DECLARATORS | {"unset"} and any(
                    re.search(r"[$`\"'\\]", w.split("=", 1)[0]) for w in words[1:] if not w.startswith("-")):
                bad.append("%d:roots:computed name" % n)
            cmd = _computed_command(stmt, text)
            if cmd:
                bad.append("%d:roots:computed command %s" % (n, cmd))
            writer = _name_writer(stmt)
            if writer:
                bad.append("%d:roots:computed operand of %s" % (n, writer))
    for name, scope, stmt in ROOT_DEFS:
        defs, reads = [], _root_reads(name)
        mention = r"(?<!\w)%s(?!\w)" % name
        for n, line, func in lines:
            code = strip_comment(line)
            if not re.search(mention, re.sub(reads, "", code)):
                continue
            if code.strip() == stmt and func == scope:
                defs.append(n)
                continue
            for st in statements(code):
                if re.search(mention, re.sub(reads, "", st)) and not _root_pass(name, st):
                    bad.append("%d:%s:named outside its one reviewed assignment" % (n, name))
                    break
        if len(defs) != 1:
            bad.append("%d:%s:%d reviewed assignments, not one" % (defs[1] if len(defs) > 1 else 0, name, len(defs)))
            continue
        at = defs[0]
        depth, chained = 0, False
        for n, line, func in lines:
            if n >= at or func != scope:
                continue
            code = strip_comment(line)
            head = FUNC_DEF.match(code)
            if head and scope and (head.group(2) or head.group(3)) == scope:
                depth, chained = 0, False   # the header of the root's own function opens its scope
                continue
            ch = None if head else _depth_change(code)
            if ch is None:
                bad.append("%d:%s:a case, subshell or function definition before its assignment" % (n, name))
                break
            depth += ch
            chained = bool(re.search(r"(?:&&|\|\||\||!)\s*$", code))
        if depth != 0 or chained:
            bad.append("%d:%s:assignment is not unconditional in its scope" % (at, name))
        for n, line, func in lines:
            if re.search(_root_reads(name), strip_comment(line)) and n != at \
                    and (n < at or (scope and func != scope)):
                bad.append("%d:%s:read before its assignment or outside its function" % (n, name))
    if len(_ROOT_CACHE) > 8:
        _ROOT_CACHE.clear()
    _ROOT_CACHE[text] = bad
    return bad


def _opaque_segment(seg):
    return OPEN in seg or ANY in seg


def target_kind(word, text, directory=False):
    """#5602: "null" for /dev/null, "file" when every expansion of `word` is under a FILE_ROOTS root with a canonical
    remainder (a directory target may be the root itself) and #5763 the scan proves every root, else "terminal"."""
    alts = expand(word, text, keep=FILE_ROOTS)
    if alts == ["/dev/null"]:
        return "null"
    # #5763: a root whose value the scan does not prove is no directory of files.
    if not alts or root_findings(text):
        return "terminal"
    for a in alts:
        m = re.fullmatch(OPEN + r"(\w+)" + CLOSE + r"((?:/[^/]+)*)", a)
        if not m or m.group(1) not in FILE_ROOTS or not (m.group(2) or directory):
            return "terminal"
        for seg in m.group(2).split("/")[1:]:
            atoms = seg_atoms(seg)
            if _opaque_segment(seg) or re.match(r"\.\.(?![\w.\-])", seg) \
                    or could_equal(atoms, seg_atoms(".")) or could_equal(atoms, seg_atoms("..")):
                return "terminal"
    return "file"


def redirect_word(text, end):
    """The shell word a redirect operator ending at `end` points at."""
    rest = text[end:].lstrip()
    words = shell_words(rest)
    return words[0] if words and rest[:1] not in ";&|<>()" else ""


def stdout_to_file(stage, text=""):
    """True when the last fd-1 output redirect in `stage` targets a proven file or /dev/null (#5602)."""
    last = None
    for m in OUT_REDIRECT.finditer(stage):
        last = redirect_word(stage, m.end(1))
    if last is None or not last or last.startswith("&"):
        return False
    return target_kind(last, text) != "terminal"


def heredoc_findings(text, names):
    """#5236: unquoted here-document bodies fed to cat or tee (which print them) that name a node value."""
    bad, lines, i = [], text.splitlines(), 0
    while i < len(lines):
        m = re.search(r"\b(cat|tee)\b[^|]*<<-?\s*(['\"]?)(\w+)\2", lines[i])
        if not m:
            i += 1
            continue
        opener, quoted, delim, j = lines[i], bool(m.group(2)), m.group(3), i + 1
        body = []
        while j < len(lines) and lines[j].strip() != delim:
            body.append(lines[j])
            j += 1
        to_file = stdout_to_file(opener[m.start():], text) or "$(" in opener[:m.start()]
        if not quoted and not to_file:
            hit = [v for v in names if re.search(r"\$\{?[#!]?%s\b" % re.escape(v), "\n".join(body))]
            if hit:
                bad.append("%d:%s<<:%s" % (i + 1, m.group(1), ",".join(sorted(hit))))
        i = j + 1
    return bad


# #5361, #5406: commands that may take a node-derived argument. Only the test builtins, the loop and case
# keywords, true, false, : and plain_id print none of their operands. A reply reaches grep, sed, tr, wc and
# the like on STDIN only (the printf or echo that feeds them is a sink and is checked on its own): as an
# ARGUMENT they print it (a file name, a format, a replacement, an invalid-identifier or numeric error).
SILENT_CONSUMERS = frozenset(("[", "[[", "test", "case", "for", "true", "false", ":", "plain_id"))
# A declaration takes name=value words: the reply may be the VALUE (nothing is printed), never the name.
DECLARATORS = frozenset(("local", "export", "readonly", "declare", "typeset"))
KEYWORDS = r"(?:(?:if|then|elif|else|while|until|do|time|!)\s+)*"


def command_segments(line):
    """Simple-command texts of a logical line, split at ; | & ( ) { } backticks and $( (also inside double
    quotes); the text of a quoted message stays with its command (#5361)."""
    segs, cur, stack, i = [], "", [], 0   # stack holds "'" or '"' or "$(" contexts
    while i < len(line):
        c = line[i]
        if c == "\\":
            cur += line[i:i + 2]
            i += 2
            continue
        top = stack[-1] if stack else None
        if top == "'":
            if c == "'":
                stack.pop()
            cur += c
        elif line.startswith("$(", i) and not line.startswith("$((", i):
            segs.append(cur)
            cur, i = "", i + 1
            stack.append("$(")
        elif top == '"':
            if c == '"':
                stack.pop()
            cur += c
        elif c == "'":
            stack.append("'")
            cur += c
        elif c == '"':
            stack.append('"')
            cur += c
        elif c in ";|&(){}`":
            if c == ")" and stack and stack[-1] == "$(":
                stack.pop()
            segs.append(cur)
            cur = ""
        else:
            cur += c
        i += 1
    segs.append(cur)
    return [s for s in segs if s.strip()]


def consumer_findings(text, names):
    """#5361: a command outside SINKS and the silent consumers that names a node-derived variable."""
    bad = []
    known = set(SILENT_CONSUMERS) | set(SINKS) | set(TAINT_SOURCES) | set(ALLOWED) | wrapper_names(text)
    for n, line, func in logical_lines(text):
        if func in ALLOWED or re.match(r"^\s*(?:ok|no|die)\(\) \{", line):
            continue
        for seg in command_segments(line):
            body = re.sub(KEYWORDS, "", seg.lstrip())
            body = re.sub(r"^(?:\w+\+?=(?:\"[^\"]*\"|'[^']*'|\S*)\s*)+", "", body)
            if body.split()[:1] and body.split()[0] in DECLARATORS:
                body = re.sub(r"(?<=\s)\w+\+?=(?:\"[^\"]*\"|'[^']*'|\S*)", "", body)
                word = body.split()[0]
                hit = [v for v in names if re.search(r"\$\{?[#!]?%s\b" % re.escape(v), body)]
                if hit:
                    bad.append("%d:%s:%s" % (n, word, ",".join(sorted(hit))))
                continue
            hit = [v for v in names if re.search(r"\$\{?[#!]?%s\b" % re.escape(v), body)]
            word = body.split(None, 1)[0] if body.split() else ""
            # #5411: a numeric test evaluates its operand as arithmetic and prints it when it is not a number.
            if hit and word in ("[", "[[", "test") and re.search(r"\s-(?:eq|ne|lt|le|gt|ge)\s", body):
                bad.append("%d:%s:%s numeric" % (n, word, ",".join(sorted(hit))))
                continue
            if hit and word and word not in known and not re.match(r"^\w+\+?=", word):
                bad.append("%d:%s:%s" % (n, word, ",".join(sorted(hit))))
    return bad


def arith_bodies(line):
    """Text of each $(( ... )) arithmetic expansion of a logical line, balanced on parentheses."""
    out, i = [], 0
    while True:
        i = line.find("$((", i)
        if i < 0:
            return out
        depth, j = 2, i + 3
        while j < len(line) and depth:
            depth += {"(": 1, ")": -1}.get(line[j], 0)
            j += 1
        out.append(line[i + 3:j - 2] if depth == 0 else line[i + 3:])
        i += 3


def arith_findings(text, names):
    """#5411: a node-derived name inside an arithmetic expansion, a substring offset or length, or an array
    subscript. Bash evaluates each as arithmetic and prints the operand when it is not a number."""
    bad = []
    for n, line, func in logical_lines(text):
        if func in ALLOWED or re.match(r"^\s*(?:ok|no|die)\(\) \{", line):
            continue
        for v in sorted(names):
            nm = re.escape(v)
            if any(re.search(r"\b%s\b" % nm, b) for b in arith_bodies(line)) \
                    or re.search(r"\$\{\w+(?:\[[^\]]*\])?:(?![-=?+])[^}]*(?:\$\{?%s\b|\b%s\b)" % (nm, nm), line) \
                    or re.search(r"[\w}]\[[^\]\s]*\$?\{?%s\b[^\]\s]*\]" % nm, line):
                bad.append("%d:arithmetic:%s" % (n, v))
    return bad


# #5413: b64 encodes its argument for a node (it is only ever called inside a command substitution that feeds a
# node channel); its pipe through base64 is exempt only while its definition is exactly this line.
B64_DEF = "b64() { printf '%s' \"$1\" | base64 | tr -d '\\n'; }"


def b64_pinned(line):
    return line.strip() == B64_DEF


# #5409: filters and dump commands that print the content of a file operand or of an input redirect.
FILE_PRINTERS = frozenset(("head", "tail", "xxd", "od", "hexdump", "strings", "more", "less", "cut", "sort", "uniq", "nl",
                           "fold", "rev", "tac", "paste", "column", "awk", "sed", "tr", "grep", "egrep", "fgrep", "zcat",
                           "bzcat", "xzcat", "diff", "comm", "join", "pr", "fmt", "expand", "unexpand", "base64", "base32",
                           "dd", "jq", "look", "cat"))


def pipeline_stages(line):
    """(stage text, operator that follows it) for the statements of a logical line outside $( ) captures and
    quotes. A stage followed by | is not the last of its pipeline."""
    out, cur, i, depth, quote = [], "", 0, 0, None
    while i < len(line):
        c = line[i]
        if c == "\\":
            cur += line[i:i + 2] if not depth else ""
            i += 2
            continue
        if quote:
            if not depth:
                cur += c
            quote = None if c == quote else quote
            i += 1
            continue
        if line.startswith("$(", i):
            depth += 1
            i += 2
            continue
        if depth:
            depth += {"(": 1, ")": -1}.get(c, 0)
            i += 1
            continue
        if c in "\"'":
            quote = c
            cur += c
        elif line.startswith("${", i):
            j = line.find("}", i)
            j = len(line) - 1 if j < 0 else j
            cur += line[i:j + 1]
            i = j
        elif c in "|;&()\n" and not ((c == "&" and (line[i - 1:i] in (">", "<") or line[i + 1:i + 2] == ">"))
                                      or (c in "()" and line[i - 1:i] == "=")):
            op = line[i:i + 2] if line[i:i + 2] in ("||", "&&", ";;") else c
            out.append((cur, op))
            cur, i = "", i + len(op) - 1
        else:
            cur += c
        i += 1
    out.append((cur, ""))
    return [(t, o) for t, o in out if t.strip()]


def stage_words(stage):
    """Words of a simple command with keywords and leading name=value words dropped."""
    body = re.sub(KEYWORDS, "", stage.lstrip())
    return re.sub(r"^(?:\w+\+?=(?:\"[^\"]*\"|'[^']*'|\S*)\s*)+", "", body)


def reads_a_file(stage):
    """The command word of a file printer stage that reads a file operand or an input redirect, else None."""
    body = stage_words(stage)
    words = body.split()
    if not words or words[0] not in FILE_PRINTERS:
        return None
    word = words[0]
    if word == "grep" and any(re.fullmatch(r"-\w*[qclL]\w*", w) for w in words[1:]):
        return None   # prints no content of the file: a status, a count or a name
    if re.search(r"(?<![<])<(?![<(])\s*\S", body):
        return word
    args = [w for w in re.sub(r"\d*>&?\S*|&>>?\S*|<<-?\S*", "", body).split()[1:] if not w.startswith("-")]
    need = 2 if word in ("sed", "awk", "grep", "egrep", "fgrep", "jq") else 1
    return word if len(args) >= need and word != "tr" else None


def file_printer_findings(text):
    """#5409: a file printer that reads a file and is not the end of a capture, a file redirect or a silent
    consumer: head, xxd, od, sed -n p, tr < FILE, grep -h . FILE ... print what a node reply left in a file."""
    bad = []
    for n, line, func in logical_lines(text):
        if func in ALLOWED or re.match(r"^\s*(?:ok|no|die)\(\) \{", line) or b64_pinned(line):
            continue
        stages, k = pipeline_stages(line), 0
        while k < len(stages):
            j = k
            while j < len(stages) - 1 and stages[j][1] == "|":
                j += 1
            pipe = [t for t, _ in stages[k:j + 1]]
            k = j + 1
            printers = [w for w in (reads_a_file(t) for t in pipe) if w]
            last = stage_words(pipe[-1]).split()
            last_word = last[0] if last else ""
            silent_end = stdout_to_file(pipe[-1], text) or last_word in ("wc", "curl") or reads_a_file_silent(pipe[-1]) \
                or dd_to_file(pipe[-1], text)
            if printers and not silent_end:
                bad.append("%d:%s:file read" % (n, printers[0]))
    return bad


def reads_a_file_silent(stage):
    words = stage_words(stage).split()
    return bool(words) and words[0] in ("grep", "egrep", "fgrep") and any(re.fullmatch(r"-\w*[qclL]\w*", w) for w in words[1:])


# #5418: a command that is not a listed file printer may still print a file; a command outside this set that names a
# file the script wrote, and does not end in a file redirect or a silent consumer, is reported. cp, install and
# cmp are in the set but silent only per silent_file_cmd (#5524): a terminal or undecidable operand, or cmp -b/-l.
SILENT_FILE_CMDS = frozenset(("rm", "mv", "cp", "chmod", "chown", "scp", "mkdir", "touch", "test", "[", "wc", "curl",
                              "mktemp", "stat", "ln", "sync", "rmdir", "install", "exec", "trap", "cmp", "ls", "true"))


REDIRECT = re.compile(r"(?:\d+|&)?(?:&>>|&>|>>|>\||>&|<&|<>|>|(?<!<)<(?!<))(?!\()\s*(?:\"[^\"]*\"|'[^']*'|[^\s;&|<>()]+)")


def operand_words(stage):
    """The words of a simple command (keywords and name=value prefixes dropped) with every redirect removed."""
    return shell_words(REDIRECT.sub(" ", stage_words(stage)))


# Options of cp, install, ln and scp that take a separate argument.
OPT_ARGS = {"cp": "S", "install": "mogS", "ln": "S", "scp": "cFiJlOoPSX"}


def _operands(words):
    """(options, operands) of a cp/install/ln/scp/mv command: -- ends the options; a short option that takes an
    argument consumes the rest of its word or the next word; -t/--target-directory is reported as ("-t", DIR)."""
    cmd, opts, ops, k, done = words[0], [], [], 1, False
    while k < len(words):
        w = words[k]
        k += 1
        if done or not w.startswith("-") or w == "-":
            ops.append(w)
        elif w == "--":
            done = True
        elif w.startswith("--"):
            name, eq, val = w.partition("=")
            if name == "--target-directory":
                opts.append(("-t", val if eq else (words[k] if k < len(words) else "")))
                k += 0 if eq else 1
            else:
                opts.append((name, val))
        else:
            for p, ch in enumerate(w[1:], 1):
                if ch == "t" and cmd != "scp" or ch in OPT_ARGS.get(cmd, ""):
                    val = w[p + 1:] or (words[k] if k < len(words) else "")
                    k += 0 if w[p + 1:] else 1
                    opts.append(("-" + ch, val))
                    break
                opts.append(("-" + ch, ""))
    return opts, ops


def silent_file_cmd(stage, text=""):
    """#5524, #5602: True when the command prints no file content. A cp, install, scp download or dd destination
    must be a proven file (target_kind); install -d makes directories; ln is silent only when what it links to is
    a proven file, so no later write through the link reaches the terminal; exec only with redirects and no
    command; trap only when its handler is silent; cmp prints differing bytes with -b or -l."""
    words = operand_words(stage)
    if not words or words[0] not in SILENT_FILE_CMDS:
        return False
    cmd = words[0]
    if cmd in ("cp", "install", "scp", "ln"):
        opts, ops = _operands(words)
        names = [o for o, _ in opts]
        if cmd == "install" and ("-d" in names or "--directory" in names):
            return True
        dirs = [v for o, v in opts if o == "-t"]
        if cmd == "ln":
            srcs = ops if dirs else ops[:-1] if len(ops) > 1 else ops
            return bool(srcs) and all(target_kind(o, text) != "terminal" for o in srcs)
        if cmd == "scp" and not dirs and ops and re.match(r"[^/]*:", ops[-1].replace("\"", "").replace("'", "")):
            return True   # an upload: nothing is written on this host
        dests = dirs or ops[-1:]
        return bool(dests) and len(ops) > (0 if dirs else 1) \
            and all(target_kind(d, text, directory=True) != "terminal" for d in dests)
    if cmd == "exec":
        return len(words) == 1
    if cmd == "trap":
        body = expand(words[1], "") if len(words) > 1 else [""]
        return len(words) > 1 and body is not None and len(body) == 1 and all(
            not (sw := operand_words(st)) or sw[0] in ("exit", "return", ":", "true") or silent_file_cmd(st, text)
            for st in statements(body[0]))
    if cmd == "cmp" and any(re.fullmatch(r"-\w*[bl]\w*|--print-bytes|--verbose", o) for o in words[1:]):
        return False
    return True


def dd_to_file(stage, text=""):
    """#5602: dd writes its input to of= and prints nothing when of= is a proven file or /dev/null."""
    words = operand_words(stage)
    of = [w[3:] for w in words[1:] if w.startswith("of=")]
    return words[:1] == ["dd"] and bool(of) and target_kind(of[-1], text) != "terminal"


OUTPUT_OPS = (">", ">>", ">|", "&>", "&>>", "<>")


def redirect_pairs(stage):
    """(operator, target word) for every redirect of `stage` outside quotes and $( ) captures; a here-document or
    here-string operator is returned with an empty word."""
    out, i, quote = [], 0, None
    while i < len(stage):
        c = stage[i]
        if c == "\\" and quote != "'":
            i += 2
            continue
        if quote:
            if c == quote:
                quote = None
            elif quote == '"' and c == "$" and stage[i + 1:i + 2] in ("(", "{"):
                i = _close(stage, i)
                continue
            i += 1
            continue
        if c in "'\"":
            quote = c
        elif c == "$" and stage[i + 1:i + 2] in ("(", "{"):
            i = _close(stage, i)
            continue
        elif c in "<>" and stage[i + 1:i + 2] != "(":
            m = re.match(r"&>>|&>|>>|>\||>&|<&|<>|<<<|<<-?|>|<", stage[i - 1:] if c == ">" and stage[i - 1:i] == "&" else stage[i:])
            op = m.group(0)
            start = i - 1 if op.startswith("&") and c == ">" else i
            i = start + len(op)
            if op.startswith("<<"):
                out.append((op, ""))
                continue
            rest = stage[i:].lstrip()
            words = shell_words(rest)
            out.append((op, words[0] if words and rest[:1] not in ";&|<>()" else ""))
            continue
        i += 1
    return out


def statements_ops(line):
    """(simple command, the operator after it) for a logical line; an operator | (not ||) joins a pipeline."""
    out, cur, i, quote = [], "", 0, None
    while i < len(line):
        c = line[i]
        if c == "\\" and quote != "'":
            cur += line[i:i + 2]
            i += 2
            continue
        if quote:
            if c == quote:
                quote = None
            elif quote == '"' and c == "$" and line[i + 1:i + 2] in ("(", "{"):
                j = _close(line, i)
                cur, i = cur + line[i:j], j
                continue
            cur += c
            i += 1
            continue
        if c in "'\"":
            quote = c
        elif c == "$" and line[i + 1:i + 2] in ("(", "{"):
            j = _close(line, i)
            cur, i = cur + line[i:j], j
            continue
        elif (c in ";&|\n" or (c in "()" and line[i - 1:i] != "=")) and not (c in "&|" and line[i - 1:i] in (">", "<")) \
                and not (c == "&" and line[i + 1:i + 2] == ">") and not (c == "(" and line[i - 1:i] in ("<", ">")):
            op = line[i:i + 2] if line[i:i + 2] in ("||", "&&", ";;", "|&") else c
            out.append((cur, op))
            cur, i = "", i + len(op)
            continue
        cur += c
        i += 1
    out.append((cur, ""))
    return [(t, o) for t, o in out if t.strip()]


def strip_comment(line):
    """`line` without a trailing comment: a # that starts a word outside quotes and captures."""
    i, quote = 0, None
    while i < len(line):
        c = line[i]
        if c == "\\" and quote != "'":
            i += 2
            continue
        if quote:
            quote = None if c == quote else quote
        elif c in "'\"":
            quote = c
        elif c == "$" and line[i + 1:i + 2] in ("(", "{"):
            i = _close(line, i)
            continue
        elif c == "#" and (i == 0 or line[i - 1] in " \t;&|("):
            return line[:i]
        i += 1
    return line


def capture_bodies(s):
    """The bodies of the $( ) command substitutions in `s`, nested ones included; arithmetic is not a capture."""
    out, i, quote = [], 0, None
    while i < len(s):
        c = s[i]
        if c == "\\" and quote != "'":
            i += 2
            continue
        if quote == "'":
            quote = None if c == "'" else quote
            i += 1
            continue
        if c == "'" and quote is None:
            quote = "'"
        elif c == '"':
            quote = None if quote == '"' else '"'
        elif c == "$" and s[i + 1:i + 2] == "(":
            j = _close(s, i)
            if not s.startswith("$((", i):
                body = s[i + 2:j - 1] if s[j - 1:j] == ")" else s[i + 2:j]
                out.append(body)
                out += capture_bodies(body)
            i = j
            continue
        i += 1
    return out


def path_parts(alt):
    """(base, segments, wide) of an expanded path. The base is a leading opaque variable's name, "/" for an
    absolute path, "~" for a tilde and "" for a relative path; empty and . segments are dropped and an
    absolute .. is resolved. A segment holding an opaque variable may span several segments: `wide` lists
    those indexes. None when a relative or opaque path holds a .. segment (undecidable)."""
    m = re.match(OPEN + "([^" + CLOSE + "]*)" + CLOSE, alt)
    if m and (alt[m.end():] == "" or alt[m.end()] == "/"):
        base, rest = m.group(1), alt[m.end():]
        base = "~" if base == "~" else base
    elif alt.startswith("/"):
        base, rest = "/", alt
    else:
        base, rest = "", alt
    segs = []
    for seg in rest.split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            if base != "/":
                return None
            segs = segs[:-1]
            continue
        if re.match(r"\.\.(?![\w.\-])", seg) and base != "/":
            return None
        segs.append(seg)
    return base, segs


def _literal(segs):
    """True when one of `segs` holds a character that is not a marker: a match that rests only on opaque or
    any-name segments says nothing about which file an operand names."""
    return any(re.search(r"[^\x01-\x07]", re.sub(OPEN + "[^" + CLOSE + "]*" + CLOSE, "", x)) for x in segs)


SEP = "\x08"


def _wide(seg):
    return OPEN in seg


@functools.lru_cache(maxsize=65536)
def _seg_equal(a, b):
    return could_equal(seg_atoms(a), seg_atoms(b))


@functools.lru_cache(maxsize=65536)
def _seg_equal_lit(a, b):
    """True when some string matches both segments with at least one literal character of `a` spelled by a
    literal character of `b` (not by a marker or a glob)."""
    x, y = seg_atoms(a), seg_atoms(b)
    seen, todo = set(), [(0, 0, False)]
    while todo:
        st = todo.pop()
        if st in seen:
            continue
        seen.add(st)
        i, j, h = st
        if i == len(x) and j == len(y):
            if h:
                return True
            continue
        if i < len(x) and x[i][1]:
            todo.append((i + 1, j, h))
        if j < len(y) and y[j][1]:
            todo.append((i, j + 1, h))
        if i < len(x) and j < len(y):
            sa, sb = x[i][0], y[j][0]
            if sa is None or sb is None or sa & sb:
                lit = sa is not None and sb is not None and len(sa) == 1 and len(sb) == 1 and not x[i][1] and not y[j][1]
                todo.append((i if x[i][1] else i + 1, j if y[j][1] else j + 1, h or lit))
    return False


def seq_match(o, p, lit=False):
    """True when the segment list o can spell exactly the segment list p; a segment holding an opaque variable
    may stand for one or more segments on either side, and its spelling must fit the segments it spans."""
    memo = {}

    def pair(a, b, h):
        if not _seg_equal(a, b):
            return None
        return h or (lit and _seg_equal_lit(a, b))

    def go(i, j, h):
        if (i, j, h) in memo:
            return memo[(i, j, h)]
        if i == len(o) or j == len(p):
            r = i == len(o) and j == len(p) and (h or not lit)
        else:
            # spanned segments are joined by SEP, a character only an opaque span can spell
            if _wide(o[i]):
                steps = [(i + 1, k, pair(o[i], SEP.join(p[j:k]), h)) for k in range(j + 1, len(p) + 1)]
            elif _wide(p[j]):
                steps = [(k, j + 1, pair(SEP.join(o[i:k]), p[j], h)) for k in range(i + 1, len(o) + 1)]
            else:
                steps = [(i + 1, j + 1, pair(o[i], p[j], h))]
            r = any(nh is not None and go(a, b, nh) for a, b, nh in steps)
        memo[(i, j, h)] = r
        return r

    return go(0, 0, False)


def has_glob(word):
    """True when a shell word holds an unquoted glob character (* ? or a [ ] class) outside $( ) and ${ }."""
    i, quote, bare = 0, None, ""
    while i < len(word):
        c = word[i]
        if c == "\\" and quote != "'":
            i += 2
            continue
        if c == "$" and word[i + 1:i + 2] in ("(", "{") and quote != "'":
            i = _close(word, i)
            continue
        if quote:
            quote = None if c == quote else quote
        elif c in "'\"":
            quote = c
        else:
            bare += c
        i += 1
    return bool(re.search(r"[*?]|\[[^\]]+\]", bare))


def names_written(op, written, glob=False):
    """#5621: True when the operand path `op` (base, segments) may name a written path or a directory above one,
    whatever the working directory is: with the same base, op is the path or one of its ancestors; an absolute op
    against a computed base must end in a leading run of the path's segments; a relative op, or a different
    computed base, must fit wholly inside the path or end in a leading run of it. A relative . is every directory.
    An opaque base with no segments (a parameter) is a stated limit."""
    if op is None:
        return True
    base, o = op
    if not o:
        return base == ""
    key = (base, tuple(o))
    return any(_names_one(key, (wbase, tuple(w)), glob) for wbase, w in written)


@functools.lru_cache(maxsize=262144)
def _names_one(op, wpath, glob):
    """names_written for one written path (cached: the same operands recur in every control)."""
    (base, o), (wbase, w) = op, wpath
    if base == wbase:
        return any(seq_match(o, w[:n]) for n in range(1, len(w) + 1))
    if not _literal(o):
        # a glob is undecidable under another base; a value with no literal spelling (a parameter, the
        # environment, a fetched value) is a stated limit
        return glob
    if base == "/" and wbase == "/":
        return False
    heads = range(1, len(o)) if base == "/" else range(0, len(o))
    if any(seq_match(o[j:], w[:n], True) for j in heads for n in range(1, len(w) + 1)):
        return True
    return base != "/" and any(seq_match(o, w[k:k + n], True) for k in range(len(w)) for n in range(1, len(w) - k + 1))


_WRITTEN_CACHE = {}


def _all_statements(text):
    """Every simple command of `text` outside heredoc bodies and comments, the bodies of its $( ) captures and of
    its trap handlers included, with die/echo/ok/no message text dropped."""
    out = []
    todo = [strip_comment(strip_messages(line)) for _, line, _ in logical_lines(text)]
    while todo:
        line = todo.pop()
        for st, _ in statements_ops(line):
            out.append(st)
            words = operand_words(st)
            if words[:1] == ["trap"] and len(words) > 1:
                body = expand(words[1], "")
                todo += body or []
        todo += capture_bodies(line)
    return out


def written_paths(text):
    """#5621: (base, segments) of every path this script may write: every output redirect at any fd (not a dup,
    not /dev/null), a cp, install, mv or ln destination (and the destination joined with each source name), an
    scp download destination and a dd of= operand; each word is expanded through the values the script assigns."""
    if text in _WRITTEN_CACHE:
        return _WRITTEN_CACHE[text]
    words = []
    for st in _all_statements(text):
        for op, w in redirect_pairs(st):
            if op in OUTPUT_OPS and w and not re.fullmatch(r"\d+|-", w):
                words.append(w)
        ow = operand_words(st)
        if ow[:1] in (["cp"], ["install"], ["mv"], ["ln"], ["scp"]):
            opts, ops = _operands(ow)
            names = [o for o, _ in opts]
            if ow[0] == "install" and ("-d" in names or "--directory" in names):
                continue
            dirs = [v for o, v in opts if o == "-t"]
            dests, srcs = (dirs, ops) if dirs else (ops[-1:], ops[:-1])
            for d in dests:
                if ow[0] == "scp" and re.match(r"[^/]*:", d.replace('"', "").replace("'", "")) \
                        or expand(d, text) == ["/dev/null"]:
                    continue
                words.append(d)
                for x in srcs:
                    for alt in expand(x, text) or []:
                        name = re.sub(OPEN + "[^" + CLOSE + "]*" + CLOSE, ANY, re.split(r"[/:]", alt)[-1])
                        if name and not name.startswith("-") and name not in (".", ".."):
                            words.append(d + "/" + name.replace(ANY, "*"))
        if ow[:1] == ["dd"]:
            words += [x[3:] for x in ow[1:] if x.startswith("of=")]
    out = []
    for w in words:
        for alt in expand(w, text) or [OPEN + "?" + CLOSE]:
            if alt == "/dev/null":
                continue
            parts = path_parts(alt)
            if parts is None:
                parts = (OPEN + "?" + CLOSE, [OPEN + "?" + CLOSE])
            if parts[1] and parts not in out:
                out.append(parts)
    if len(_WRITTEN_CACHE) > 8:
        _WRITTEN_CACHE.clear()
    _WRITTEN_CACHE[text] = out
    return out


def stage_operands(stage, text):
    """The operand paths of a simple command: every word after the command word (input redirects included,
    output redirects dropped), expanded, then split again at white space, quotes and = < > | ; & ( ); an
    option word -xVALUE is also read as VALUE."""
    words = operand_words(stage)[1:]
    words += [w for op, w in redirect_pairs(stage) if op in ("<", "<>") and w]
    out = []
    for w in words:
        alts = expand(w, text)
        glob = has_glob(w)
        for alt in alts if alts is not None else [OPEN + "?" + CLOSE]:
            pieces = [x for x in re.split(r"[\s'\"=<>|;&()]+", alt) if x]
            pieces += [x[2:] for x in pieces if re.match(r"-\w[^/.]*[/.]", x)]
            out += [(path_parts(x), glob) for x in pieces]
    return out


DIR_CHANGES = ("cd", "pushd", "popd")
QUIET = ("printf", "echo", "ok", "no", "die", "case", "[", "[[", "test", "local", "export", "readonly", "declare",
         "typeset") + DIR_CHANGES


def reads_written(stage, text, written):
    return any(names_written(o, written, g) for o, g in stage_operands(stage, text))


def unlisted_reader_findings(text):
    """#5418, #5525, #5621: a stage outside FILE_PRINTERS and the silent commands whose operands may name a path
    this script writes (written_paths) is a reader the scan does not model, so it is reported unless its output
    goes to a proven file. Paths are compared by name, so no change of directory (cd, pushd, popd, env --chdir,
    a subshell) can hide one. In a $( ) capture, a printer or an unlisted reader of a written path is reported
    unless its pipeline ends in a file redirect or a silent consumer: the captured text may be printed."""
    written = written_paths(text)
    bad = []
    for n, line, func in logical_lines(text):
        if func in ALLOWED or re.match(r"^\s*(?:ok|no|die)\(\) \{", line) or b64_pinned(line):
            continue
        stages = statements_ops(strip_comment(strip_messages(line)))
        for stage, _ in list(stages):
            tw = operand_words(stage)
            if tw[:1] == ["trap"] and len(tw) > 1:
                # a trap handler runs later as code: its statements are judged like the line's own
                for body in expand(tw[1], "") or []:
                    stages += statements_ops(strip_comment(body))
        for stage, _ in stages:
            words = stage_words(stage).split()
            word = words[0] if words else ""
            if word == "exec" and any(op in ("<", "<>") and w and any(names_written(o, written, has_glob(w))
                                                                       for o, _ in stage_operands("x " + w, text))
                                      for op, w in redirect_pairs(stage)):
                # #5621: exec opens a written file on a descriptor a later command reads
                bad.append("%d:exec:written file opened for reading" % n)
                continue
            if word in ("cp", "install", "scp", "ln") and not silent_file_cmd(stage, text):
                # #5602: whatever it copies, a destination not proven a file is the terminal
                bad.append("%d:%s:copy to a target not proven a file" % (n, word))
                continue
            if not word or word in FILE_PRINTERS or silent_file_cmd(stage, text) or word in QUIET \
                    or not operand_words(stage):
                continue
            if reads_written(stage, text, written) and not stdout_to_file(stage, text):
                bad.append("%d:%s:unlisted file reader" % (n, word))
        for body in capture_bodies(strip_comment(strip_messages(line))):
            pipe = []
            for stage, op in statements_ops(body):
                pipe.append(stage)
                if op in ("|", "|&"):
                    continue
                last = operand_words(pipe[-1])
                silent_end = stdout_to_file(pipe[-1], text) or last[:1] in (["wc"], ["curl"]) \
                    or reads_a_file_silent(pipe[-1]) or dd_to_file(pipe[-1], text)
                for st in pipe:
                    w = operand_words(st)
                    if not w or w[0] in QUIET or (w[0] not in FILE_PRINTERS and silent_file_cmd(st, text)):
                        continue
                    if not silent_end and reads_written(st, text, written):
                        bad.append("%d:%s:capture of a written file" % (n, w[0]))
                        break
                pipe = []
    return bad


def taint_findings(text, names):
    """Sink commands whose arguments name a node-derived variable other than through an allowed helper.
    #5236: a positional parameter, an indirect expansion, a pipe into anything but a silent or node-bound
    consumer, a write to /dev/stderr or /dev/tty, and a here-document to cat or tee all count."""
    bad, checked = [], 0
    helper = r"\$\((?:%s)(?: \"\$\{?\w+\}?\")+\)" % "|".join(sorted(ALLOWED))
    for n, line, func in logical_lines(text):
        if func in ALLOWED or re.match(r"^\s*(?:ok|no|die)\(\) \{", line) or b64_pinned(line):
            continue
        for cmd, args, after, before in _segments(line, "|".join(SINKS)):
            if cmd in ("echo", "printf", "cat"):
                # Output into a capture is not the terminal.
                if before.count("$(") > before.count(")"):
                    continue
                # A pipe is not the terminal only when it feeds a silent or node-bound consumer.
                if after.startswith("|") and not after.startswith("||") \
                        and re.match(r"\|\s*(?:grep\s+-q\w*\s|curl\s|base64\b[^|]*\|\s*curl\s)", after):
                    continue
                # A file is not the terminal; the last output redirect decides (#5412).
                if stdout_to_file(args, text):
                    continue
            checked += 1
            rest = re.sub(helper, "", args)
            hit = [v for v in names if re.search(r"\$\{?[#!]?%s\b" % re.escape(v), rest)]
            # A function argument reaches the sink unseen by the name-based taint: outside the output
            # primitives and the reply helpers, no positional parameter may reach a terminal line.
            if re.search(r"\$(?:\{[#!]?)?[1-9*@]", rest):
                hit.append("positional")
            if re.search(r"\$\{!\w", rest):
                hit.append("indirect")
            # A file read in a terminal line may print a node-fetched file (a peer key fetched by scp).
            if re.search(r"\$\(\s*(?:cat\b|<)", rest):
                hit.append("file read")
            # #5362: nor may any other command substitution (head, sed, od ... of a file the reply was
            # written to), or a cat of a file operand, appear in a terminal line.
            if re.search(r"\$\((?!\()", rest):
                hit.append("command substitution")
            if "`" in rest:
                hit.append("backtick substitution")
            if cmd == "cat" and re.search(r"(?:^|\s)(?:<\s*)?[^\s<>|&;-]", re.sub(r"\d*>&?\S*|<<-?\S*", "", args)):
                hit.append("file operand")
            if hit:
                bad.append("%d:%s:%s" % (n, cmd, ",".join(sorted(hit))))
    bad += root_findings(text)
    bad += heredoc_findings(text, names)
    bad += consumer_findings(text, names)
    bad += arith_findings(text, names)
    bad += file_printer_findings(text)
    bad += unlisted_reader_findings(text)
    return bad, checked


BANNED_CONSTRUCTS = (
    (r"(?<![\w-])eval(?![\w-])", "eval"), (r"<<<", "here-string"), (r"(?<![\w-])printf\s+-v", "printf -v"),
    (r"\$\{!", "indirect expansion"), (r"(?<![\w-])(?:declare|local|typeset)\s+-\w*n", "nameref"),
    (r"(?<![\w-])read(?![\w-])", "read"), (r"(?<![\w-])(?:mapfile|readarray)(?![\w-])", "mapfile"),
    (r"(?<![\w-])tee(?![\w-])", "tee"), (r"(?<![\w-])source(?![\w-])|(?:^|[;&|]\s*)\.\s", "source"),
    # #5359: an assignment whose target the taint scan cannot record.
    (r"(?<![\w$])\w+\[[^\]]*\]\+?=", "indexed assignment"),
    (r"(?<![\w$])\w+\+?=[^\s]*\\\s", "escaped space in an assignment"),
    (r"\$\{\w+:?=", "default-assign expansion"),
    # #5410: let and the (( command evaluate their operand as arithmetic and print it in a syntax error.
    (r"\$\{\w+:?\?", "error expansion"),
    # #5407: a process substitution runs a command the scan does not follow, and its redirect is no file.
    (r"(?<![\w$\\])[<>]\(", "process substitution"),
    # #5408: a backtick command substitution is as unreadable to the scan as $( ) is readable.
    (r"`", "backtick substitution"),
    (r"(?<![\w-])let(?![\w-])", "let"), (r"(?<![\w$])\(\(", "arithmetic command"),
)


def construct_findings(text):
    """#5236: lines (outside comments and quoted messages) using a construct the taint scan cannot follow."""
    bad = []
    for n, line, func in logical_lines(text):
        if func in ("main",):
            continue
        # Drop double-quoted message text that holds no expansion, and single-quoted literals.
        code = re.sub(r"'[^']*'", "''", line)
        code = re.sub(r'"[^"$`]*"', '""', code)
        code = re.sub(r"(?:^|\s)#.*$", "", code)  # a trailing comment
        for rx, label in BANNED_CONSTRUCTS:
            if re.search(rx, code):
                bad.append("%d:%s" % (n, label))
        # A here-document is allowed only as a script fed to a node (node_sh); any other reader may print it.
        # #5655: every operator counts, whatever the spelling of its delimiter, and one per line.
        ops = heredoc_ops(line)
        if ops and (len(ops) > 1 or not re.search(r"(?<![\w-])node_sh\s[^<]*<<", line)):
            bad.append("%d:here-document" % n)
    # #5655: an unterminated body is read as code (see heredoc_scan) and is itself a finding.
    bad += ["%d:unterminated here-document %s" % (at, delim) for at, delim in heredoc_scan(text)[1]]
    # #5655: bash runs a command substitution of an unquoted body on this machine before the body is sent.
    for k, raw, quoted, _ in heredoc_body_lines(text):
        if not quoted and re.search(r"(?<!\\)(?:\\\\)*(?:\$\((?!\()|`)", raw):
            bad.append("%d:command substitution in a here-document" % k)
    return bad


def closed_world_taint(fs):
    """Source-level closed world: no node-derived variable reaches ok/no/die/echo/printf/cat/tee except
    through reply_status, reply_len or reply_version, and no construct the scan cannot follow is used."""
    names = tainted_names(fs)
    expect = {"code", "versions", "api_key", "resp", "qcode", "qjson", "QID", "landed", "sresp", "scode", "sjson",
              "SID", "lvl", "pg_ver", "age_ver", "vec_ver"}
    probe("V1 the taint scan finds every node-derived variable (not vacuous)", expect <= names, str(sorted(expect - names)))
    bad, checked = taint_findings(fs, names)
    probe("V1 no node-derived variable reaches a terminal line except through reply_status/reply_len/reply_version",
          not bad, " ".join(bad[:8]))
    probe("V1 the taint scan checks the terminal lines (not vacuous)", checked >= 60, str(checked))
    wrap = lambda body: fs + "\nprobe_fn() {\n%s\n}\n" % body
    run_def = 'run_dir="$REPO_ROOT/.local-runs/do-hive-runs/$(date -u +%Y-%m-%dT%H-%M-%SZ)/loadgen"\n'
    in_loadgen = lambda body: fs.replace(run_def, run_def + body + "\n", 1)
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
                        ("an echo to stderr", 'echo "$code" >&2'),
                        # #5236: the union of the bypass forms of the round-10 reviews.
                        ("a function argument", 'say() { no "x $1"; }\nsay "$qjson"'),
                        ("a function argument via $*", 'show() { no "got $*"; }\nshow "$qjson"'),
                        ("a function defined outside verify", 'say2() { no "x $1"; }\nverify2() { say2 "$qjson"; }'),
                        ("a read into a variable", 'read -r t <<< "$qjson"\nno "x $t"'),
                        ("a mapfile into an array", 'mapfile -t t <<< "$qjson"\nno "x ${t[0]}"'),
                        ("a for loop variable", 'for t in $qjson; do no "x $t"; done'),
                        # #5360: a function that wraps a node channel is a taint source of its own.
                        ("a wrapper around a channel", 'fetch() { on_node "$1" "cat x" 2>/dev/null; }\nt=$(fetch h)\nno "x $t"'),
                        ("a wrapper of a wrapper", 'f1() { node_get "$1" "$2"; }\nf2() { f1 "$1" x; }\nt=$(f2 h)\nno "x $t"'),
                        ("a wrapper around curl", 'g1() { curl -s "$1" 2>/dev/null; }\nt="$(g1 u)"\nno "x $t"'),
                        ("an append assignment", 't=a\nt+=$qjson\nno "x $t"'),
                        ("printf -v", "printf -v t '%s' \"$qjson\"\nno \"x $t\""),
                        ("an indirect expansion", 't=qjson\nno "x ${!t}"'),
                        ("a printf piped to cat", "printf '%s' \"$qjson\" | cat"),
                        ("an echo to /dev/stderr", 'echo "$qjson" > /dev/stderr'),
                        ("an echo to /dev/tty", 'echo "$qjson" >/dev/tty'),
                        ("a redirect before the command", '>&2 echo "$qjson"'),
                        ("a pipe into tee", "printf '%s\\n' \"$qjson\" | tee /dev/stderr >/dev/null"),
                        ("a here-string to cat", 'cat <<< "$qjson"'),
                        ("a here-document to cat", 'cat <<EOT\nx $qjson\nEOT'),
                        ("a printf %b of a reply", "printf '%b\\n' \"$resp\""),
                        ("an echo inside an if", 'if true; then echo "$lvl"; fi'),
                        ("a reply-derived helper argument", 'no "x $(reply_len "${qjson:0:64}")"'),
                        ("a file read in a failure line", 'no "x $(cat "$OUT_DIR/$pub")"'),
                        # #5361: a reply handed to a command outside SINKS.
                        ("jq with the reply as an argument", "jq -rn --arg x \"$qjson\" '$x'"),
                        ("awk with the reply as a variable", "awk -v x=\"$qjson\" 'BEGIN{print x}'"),
                        ("logger with the reply", 'logger "$qjson"'),
                        ("an unknown command in a capture", 'z="$(frobnicate "$qjson")"'),
                        ("an unknown command after an if", 'if true; then frobnicate "$qjson"; fi'),
                        ("an unknown command after an assignment", 'v=1 frobnicate "$qjson"'),
                        ("an unknown command after a pipe", "printf x | frobnicate \"$qjson\""),
                        ("jq after a pipe", "printf x | jq --arg v \"$qjson\" -n '$v'"),
                        # #5362: a reply written to a file and printed later.
                        ("a reply file printed by cat", "printf '%s' \"$qjson\" > \"$OUT_DIR/r\"\ncat \"$OUT_DIR/r\""),
                        ("a reply file read by head in a failure line", "printf '%s' \"$qjson\" > \"$OUT_DIR/r\"\nno \"x $(head -c 99 \"$OUT_DIR/r\")\""),
                        ("a reply file read by sed in a failure line", 'no "x $(sed -n 1p "$OUT_DIR/r")"'),
                        ("a reply file read by redirect-cat", 'cat < "$OUT_DIR/r"'),
                        ("a command substitution in a PASS line", 'ok "x $(od -c "$OUT_DIR/r")"'),
                        # #5406: commands that print an ARGUMENT are not silent consumers of a reply.
                        ("sed with the reply in the replacement", 'printf x | sed "s/x/$qjson/"'),
                        ("seq with the reply as the format", 'seq -f "$qjson" 1'),
                        ("wc with the reply as a file name", 'wc -c "$qjson"'),
                        ("grep with the reply as a file name", 'grep -q x "$qjson"'),
                        ("grep with the reply as the pattern", 'grep -q "$qjson" "$OUT_DIR/r"'),
                        ("shift with the reply", 'shift "$qjson"'),
                        ("return with the reply", 'return "$qjson"'),
                        ("exit with the reply", 'exit "$qjson"'),
                        ("export with the reply as the name", 'export "$qjson"'),
                        ("local with the reply as the name", 'local "$qjson"'),
                        ("tr with the reply as a set", 'echo abc | tr abc "$qjson"'),
                        ("unset with the reply", 'unset "$qjson"'),
                        ("readonly with the reply as the name", 'readonly "$qjson"'),
                        # #5409: a file printed by a command other than cat, as a line of its own or at the end of a pipeline.
                        ("head of a reply file", 'head -c 99 "$OUT_DIR/r"'), ("xxd of a reply file", 'xxd "$OUT_DIR/r"'),
                        ("sed -n p of a reply file", 'sed -n p "$OUT_DIR/r"'), ("tr from a reply file", 'tr a b < "$OUT_DIR/r"'),
                        ("grep -h of a reply file", 'grep -h . "$OUT_DIR/r"'), ("awk of a reply file", "awk 1 \"$OUT_DIR/r\""),
                        ("cut of a reply file", 'cut -c1-9 "$OUT_DIR/r"'), ("sort of a reply file", 'sort "$OUT_DIR/r"'),
                        ("jq of a reply file", 'jq . "$OUT_DIR/r"'), ("od of a reply file after then", 'if true; then od -c "$OUT_DIR/r"; fi'),
                        ("head after &&", 'true && head -c 9 "$OUT_DIR/r"'), ("head after ||", 'false || head -c 9 "$OUT_DIR/r"'),
                        ("head piped into cat", 'head -c 9 "$OUT_DIR/r" | cat'),
                        ("head piped into tr", "head -c 9 \"$OUT_DIR/r\" | tr -d x"),
                        ("a subshell printing a file", '( strings "$OUT_DIR/r" )'),
                        # #5414: a wrapper around a node channel in every function spelling is a taint source.
                        ("a function keyword wrapper", 'function pf { node_sh 0 </dev/null; }\nt=$(pf)\nno "x $t"'),
                        ("a spaced name () wrapper", 'pf2 () { node_sh 0 </dev/null; }\nt=$(pf2)\nno "x $t"'),
                        ("a function keyword and parentheses wrapper", 'function pf3() { node_sh 0 </dev/null; }\nt=$(pf3)\nno "x $t"'),
                        ("a wrapper with the brace on the next line", 'pf4()\n{\n node_sh 0 </dev/null\n}\nt=$(pf4)\nno "x $t"'),
                        ("an indented wrapper", '  pf5() { node_sh 0 </dev/null; }\n  t=$(pf5)\n  no "x $t"'),
                        ("a multi-line wrapper of a wrapper", 'pf6() {\n  node_get 0 x\n}\npf7 () {\n  pf6\n}\nt=$(pf7)\nno "x $t"'),
                        ("a one-line helper that borrows an allowed name", 'reply_len() { :; }\nno "x $qjson"'),
                        # #5413: base64 is a filter, not a node-bound consumer: only a pipe on into curl is.
                        ("a bare pipe into base64", 'printf %s "$qjson" | base64'),
                        ("a pipe into base64 -w0", 'echo "$qjson" | base64 -w0'),
                        ("a pipe through base64 into cat", 'printf %s "$qjson" | base64 | cat'),
                        ("a pipe through base64 into tr", "printf %s \"$qjson\" | base64 | tr -d '\\n'"),
                        ("a b64 helper that prints its argument", "b64() { printf '%s' \"$1\" | base64; }"),
                        # #5408: a backtick command substitution is a command substitution.
                        ("a backtick substitution in a PASS line", 'ok "x `head -c 9 \\"$OUT_DIR/r\\"`"'),
                        ("a backtick substitution in a failure line", 'no "x `sed -n 1p "$OUT_DIR/r"`"'),
                        ("a backtick substitution in an echo", 'echo `od -c "$OUT_DIR/r"`'),
                        # #5412: the LAST output redirect decides, >> and >| are redirects, and only a plain path is a file.
                        ("an append to /dev/stderr", 'printf %s "$qjson" >> /dev/stderr'),
                        ("a clobber to /dev/stderr", 'printf %s "$qjson" >| /dev/stderr'),
                        ("a file and then a dup to stderr", 'printf %s "$qjson" >/dev/null >&2'),
                        ("a file and then 1>&2", 'printf %s "$qjson" > "$OUT_DIR/r" 1>&2'),
                        ("a write to a pty", "printf '%s\\n' \"$qjson\" > /dev/pts/0"),
                        ("a write to the console", 'printf %s "$qjson" > /dev/console'),
                        ("a write to a serial tty", 'printf %s "$qjson" > /dev/ttyS0'),
                        ("a write to a virtual console", 'printf %s "$qjson" > /dev/vcs1'),
                        ("a write to a command-computed tty", "printf '%s\\n' \"$qjson\" > \"$(tty)\""),
                        ("a write to a backtick-computed tty", 'printf %s "$qjson" > `tty`'),
                        ("an &> to /dev/stderr", 'printf %s "$qjson" &> /dev/stderr'),
                        ("an &>> to /dev/stderr", 'printf %s "$qjson" &>> /dev/stderr'),
                        ("a here-document appended to /dev/stderr", 'cat >> /dev/stderr <<EOT\nx $qjson\nEOT'),
                        ("a here-document to a pty", 'cat > /dev/pts/1 <<EOT\nx $qjson\nEOT'),
                        # #5411: arithmetic and expansion-error contexts print the operand that fails.
                        ("an arithmetic expansion", ': $((qjson + 0))'),
                        ("an arithmetic expansion with a dollar", 'n=$(( $qjson * 2 ))'),
                        ("a substring offset", 's=abcdef\n: "${s:$qjson:1}"'),
                        ("a substring length", 's=abcdef\n: "${s:0:${qjson}}"'),
                        ("an array subscript", 'a=(1 2)\n: "${a[$qjson]}"'),
                        ("a numeric test with [", '[ "$qjson" -eq 1 ]'),
                        ("a numeric test with [[", '[[ $qjson -lt 1 ]]'),
                        ("a numeric test with the reply as the right operand", '[ 1 -ne "$qjson" ]'),
                        # #5411: further probes of the class (own, measured in bash): each prints the reply.
                        ("trap with the reply", 'trap "$qjson" EXIT'), ("cd with the reply", 'cd "$qjson"'),
                        ("kill with the reply", 'kill "$qjson"'), ("sleep with the reply", 'sleep "$qjson"'),
                        ("type with the reply", 'type "$qjson"'), ("alias with the reply", 'alias "$qjson"'),
                        ("printf with the reply as the format", 'printf "$qjson"'),
                        ("command -v with the reply", 'command -v "$qjson"'),
                        ("declare with the reply as the name", 'declare "$qjson"'),
                        # #5418: a redirect target the scan cannot decide is reported; a reader it does not model too.
                        ("a write to a target held in a variable", 'dest=/dev/stderr\nprintf %s "$qjson" > "$dest"'),
                        ("a write to an unquoted variable target", 'dest=/dev/stderr\nprintf %s "$qjson" > $dest'),
                        ("a write to a braced variable target", 'dest=/dev/stderr\nprintf %s "$qjson" >"${dest}"'),
                        ("a write to a variable target with a suffix", 'printf %s "$qjson" > "$dest.log"'),
                        ("a write to a tilde target", 'printf %s "$qjson" > ~/r'),
                        # #5523: a target the scan cannot decide is the terminal.
                        ("a write through a dotdot segment", 'printf %s "$qjson" > "$OUT_DIR/../../../../dev/tty"'),
                        ("a write through a segment held in a variable", 'x=../../../../dev/stderr\nprintf %s "$qjson" > "$OUT_DIR/$x"'),
                        ("a write through a dotdot after a variable", 'printf %s "$qjson" > "$OUT_DIR/..$n/x"'),
                        ("a literal path with a dotdot segment", 'printf %s "$qjson" > /var/../dev/tty'),
                        # #5524: cp, install and cmp can print a file.
                        ("cp of a written file to the tty", 'printf %s x > "$OUT_DIR/r9"\ncp "$OUT_DIR/r9" /dev/tty'),
                        ("install of a written file to stdout", 'printf %s x > "$OUT_DIR/r9"\ninstall -m 0644 "$OUT_DIR/r9" /dev/stdout'),
                        ("cp of a written file to a bare variable", 'printf %s x > "$OUT_DIR/r9"\ncp "$OUT_DIR/r9" "$dest"'),
                        ("install of a written file under a dotdot path", 'printf %s x > "$OUT_DIR/r9"\ninstall "$OUT_DIR/r9" "$OUT_DIR/../../dev/tty"'),
                        ("cmp -b of a written file", 'printf %s x > "$OUT_DIR/r9"\ncmp -b "$OUT_DIR/r9" "$OUT_DIR/author.id"'),
                        ("cmp -l of a written file", 'printf %s x > "$OUT_DIR/r9"\ncmp -l "$OUT_DIR/r9" "$OUT_DIR/author.id"'),
                        ("cmp --verbose of a written file", 'printf %s x > "$OUT_DIR/r9"\ncmp --verbose "$OUT_DIR/r9" "$OUT_DIR/author.id"'),
                        ("a write to a glob target", 'printf %s "$qjson" > /dev/tty[0-9]*'),
                        ("a write to a brace-expanded target", 'printf %s "$qjson" > /dev/{stderr,null}'),
                        ("an append to a target held in a variable", 'dest=/dev/stderr\nprintf %s "$qjson" >> "$dest"'),
                        ("a here-document to a target held in a variable", 'dest=/dev/pts/1\ncat > "$dest" <<EOT\nx $qjson\nEOT'),
                        # #5525: other spellings of a written path.
                        ("a braced spelling of a written path", 'printf %s x > "$OUT_DIR/r9"\niconv "${OUT_DIR}/r9"'),
                        ("a split-quote spelling of a written path", 'printf %s x > "$OUT_DIR/r9"\niconv "$OUT_DIR"/r9'),
                        ("a read of a literal written path", 'printf %s x > /var/tmp/r9\niconv /var/tmp/r9'),
                        ("a read after cd into the written directory", 'printf %s x > "$OUT_DIR/r9"\ncd "$OUT_DIR" && iconv r9'),
                        ("a ./ read after cd into the written directory", 'printf %s x > "$OUT_DIR/r9"\ncd -- "$OUT_DIR"\niconv ./r9'),
                        ("a read by perl", 'perl -pe 1 "$OUT_DIR/author.id"'),
                        ("a read by python", "python3 -c 'import sys;print(open(sys.argv[1]).read())' \"$OUT_DIR/author.pub\""),
                        ("a read by bat", 'bat "$OUT_DIR/author.id"'),
                        ("a read by an input redirect", 'lolcat < "$OUT_DIR/author.id"'),
                        ("a read of a file the probe wrote", 'printf %s x > "$OUT_DIR/r9"\nbat "$OUT_DIR/r9"'),
                        ("a read of a peers file", 'batcat "$OUT_DIR/peers.conf.node$n"'),
                        ("an unlisted reader at the end of a pipe", 'true | perl -pe 1 "$OUT_DIR/author.id"'),
                        # #5602: a target is a file only when it is proven under a FILE_ROOTS root with a canonical
                        # remainder. The round-15 review mutants M1-M4, M8, M10, M12, then neighbours of the class.
                        ("M1 cp to a doubled-slash tty", 'printf %s x > "$OUT_DIR/r9"\ncp "$OUT_DIR/r9" //dev/tty'),
                        ("M2 cp to a dot-segment stdout", 'printf %s x > "$OUT_DIR/r9"\ncp "$OUT_DIR/r9" /./dev/stdout'),
                        ("M3 a write to a doubled-slash tty", 'printf %s "$qjson" > //dev/tty'),
                        ("M4 a write to a dot-segment tty", 'printf %s "$qjson" > /./dev/tty'),
                        ("M8 cp into a doubled-slash fd directory", 'printf %s x > "$OUT_DIR/r9"\ncp --target-directory=//dev/fd "$OUT_DIR/r9"'),
                        ("M10 a write to a doubled-slash proc fd", 'printf %s "$qjson" > //proc/self/fd/2'),
                        ("M12 install to a doubled-slash stdout", 'printf %s x > "$OUT_DIR/r9"\ninstall -m 0644 "$OUT_DIR/r9" //dev/stdout'),
                        ("a write to /dev/fd/2", 'printf %s "$qjson" > /dev/fd/2'),
                        ("a write to /proc/self/fd/1", 'printf %s "$qjson" > /proc/self/fd/1'),
                        ("a write to a quoted /dev/stderr", 'printf %s "$qjson" > "/dev/stderr"'),
                        ("a write to an unquoted /dev/stderr", 'printf %s "$qjson" > /dev/stderr'),
                        ("a write to a variable never assigned", 'printf %s "$qjson" > "$LOGF"'),
                        ("a write to a variable holding a doubled-slash path", 'd=//dev\nprintf %s "$qjson" > "$d/tty"'),
                        ("an append to a doubled-slash tty", 'printf %s "$qjson" >> //dev/tty'),
                        ("a clobber write to a dot-segment tty", 'printf %s "$qjson" >| /./dev/tty'),
                        ("an &> to a doubled-slash stderr", 'printf %s "$qjson" &> //dev/stderr'),
                        ("a here-document to a doubled-slash tty", 'cat > //dev/tty <<EOT\nx $qjson\nEOT'),
                        ("a write to a dot segment under the root", 'printf %s "$qjson" > "$OUT_DIR/./r"'),
                        ("a write to an empty segment under the root", 'printf %s "$qjson" > "$OUT_DIR//r"'),
                        ("a write to the root itself", 'printf %s "$qjson" > "$OUT_DIR"'),
                        ("a write under a directory that is not a root", 'printf %s "$qjson" > "$HERE/r"'),
                        ("a write through a segment that may be dot", 'x=.\nprintf %s "$qjson" > "$OUT_DIR/$x"'),
                        ("a write through a glob segment", 'printf %s "$qjson" > "$OUT_DIR"/r*'),
                        ("dd of a written file to a doubled-slash tty", 'printf %s x > "$OUT_DIR/r9"\ndd if="$OUT_DIR/r9" of=//dev/tty'),
                        ("dd from stdin to the tty", 'printf %s "$qjson" | dd of=/dev/tty'),
                        ("cp -t into the fd directory", 'printf %s x > "$OUT_DIR/r9"\ncp -t /dev/fd "$OUT_DIR/r9"'),
                        ("install -D to a dot-segment stdout", 'printf %s x > "$OUT_DIR/r9"\ninstall -D "$OUT_DIR/r9" /./dev/stdout'),
                        ("ln of the tty into a written path", 'ln -sf /dev/tty "$OUT_DIR/r9"\nprintf %s "$qjson" > "$OUT_DIR/r9"'),
                        ("an scp download to the tty", 'scp -q h:/etc/x //dev/tty'),
                        ("an scp download to a variable never assigned", 'scp -q h:/etc/x "$DESTF"'),
                        ("an scp download named by an array the script does not check", 'ARR=(a)\nscp -q h:/x "$OUT_DIR/${ARR[0]}.pub"'),
                        ("an append to the checked identity array", 'FED_IDS+=(x)\nscp -q h:/x "$OUT_DIR/${FED_IDS[0]}.pub"'),
                        ("a trap whose handler prints a written file", 'printf %s x > "$OUT_DIR/r9"\ntrap \'iconv "$OUT_DIR/r9"\' EXIT'),
                        ("exec of a command on a written file", 'printf %s x > "$OUT_DIR/r9"\nexec iconv "$OUT_DIR/r9"'),
                        # #5621: a read of a written file is decided by name against every written path, whatever the spelling and
                        # whatever the working directory. The round-15 review mutants M5-M7, the reproducers, then neighbours.
                        ('M5 a dot segment in the operand', 'printf %s x > "$OUT_DIR/r9"\niconv "$OUT_DIR/./r9"'),
                        ('M6 a glob that matches the written name', 'printf %s x > "$OUT_DIR/r9"\niconv "$OUT_DIR"/r[9]'),
                        ('M7 pushd into the written directory', 'printf %s x > "$OUT_DIR/r9"\npushd "$OUT_DIR" >/dev/null && iconv r9'),
                        ('a variable holding the written path', 'printf %s x > "$OUT_DIR/r9"\nf="$OUT_DIR/r9"\niconv "$f"'),
                        ('a variable built from a variable', 'printf %s x > "$OUT_DIR/r9"\nd="$OUT_DIR"\nf="$d/r9"\niconv "$f"'),
                        ('find over the written directory', 'printf %s x > "$OUT_DIR/r9"\nfind "$OUT_DIR" -type f -exec iconv {} +'),
                        ('a relative path after cd into a parent', 'cd "$HERE" && iconv crypto/out/author.id'),
                        ('a relative path after cd into the next directory', 'printf %s x > "$OUT_DIR/r9"\ncd "$HERE/crypto" && iconv out/r9'),
                        ('a read after cd into another directory', 'printf %s x > "$OUT_DIR/r9"\ncd "$HERE" && iconv r9'),
                        ('a capture of a written file by cat', 'printf %s x > "$OUT_DIR/r9"\nt="$(cat "$OUT_DIR/r9")"\nno "x $t"'),
                        ('a capture of a written file by iconv', 'printf %s x > "$OUT_DIR/r9"\nt="$(iconv "$OUT_DIR/r9")"'),
                        ('a capture by head', 'printf %s x > "$OUT_DIR/r9"\nt="$(head -c 9 "$OUT_DIR/r9")"'),
                        ('a capture by tail', 'printf %s x > "$OUT_DIR/r9"\nt="$(tail -n 1 "$OUT_DIR/r9")"'),
                        ('a capture by od', 'printf %s x > "$OUT_DIR/r9"\nt="$(od -c "$OUT_DIR/r9")"'),
                        ('a capture by xxd', 'printf %s x > "$OUT_DIR/r9"\nt="$(xxd "$OUT_DIR/r9")"'),
                        ('a capture by strings', 'printf %s x > "$OUT_DIR/r9"\nt="$(strings "$OUT_DIR/r9")"'),
                        ('a capture by base64', 'printf %s x > "$OUT_DIR/r9"\nt="$(base64 "$OUT_DIR/r9")"'),
                        ('a capture by tr with an input redirect', 'printf %s x > "$OUT_DIR/r9"\nt="$(tr -d x < "$OUT_DIR/r9")"'),
                        ('a capture through a pipe of readers', 'printf %s x > "$OUT_DIR/r9"\nt="$(iconv "$OUT_DIR/r9" | tr a b)"'),
                        ('a while read loop over a written file', 'printf %s x > "$OUT_DIR/r9"\nwhile read -r l; do :; done < "$OUT_DIR/r9"'),
                        ('mapfile from a written file', 'printf %s x > "$OUT_DIR/r9"\nmapfile -t a < "$OUT_DIR/r9"'),
                        ('source of a written file', 'printf %s x > "$OUT_DIR/r9"\nsource "$OUT_DIR/r9"'),
                        ('a dot source of a written file', 'printf %s x > "$OUT_DIR/r9"\n. "$OUT_DIR/r9"'),
                        ('cd - back into the written directory', 'printf %s x > "$OUT_DIR/r9"\ncd "$OUT_DIR"\ncd /\ncd - >/dev/null && iconv r9'),
                        ('pushd +1 into the written directory', 'printf %s x > "$OUT_DIR/r9"\npushd "$OUT_DIR" >/dev/null\npushd / >/dev/null\npushd +1 >/dev/null && iconv r9'),
                        ('a subshell cd into the written directory', 'printf %s x > "$OUT_DIR/r9"\n(cd "$OUT_DIR" && iconv r9)'),
                        ('env --chdir into the written directory', 'printf %s x > "$OUT_DIR/r9"\nenv --chdir="$OUT_DIR" iconv r9'),
                        ('env -C into the written directory', 'printf %s x > "$OUT_DIR/r9"\nenv -C "$OUT_DIR" iconv r9'),
                        ('a relative .. operand', 'printf %s x > "$OUT_DIR/r9"\ncd "$OUT_DIR/sub" 2>/dev/null; iconv ../r9'),
                        ('a bare glob after cd', 'printf %s x > "$OUT_DIR/r9"\ncd "$OUT_DIR" && iconv *'),
                        ('a ? glob of the written name', 'printf %s x > "$OUT_DIR/r9"\niconv "$OUT_DIR"/r?'),
                        ('M9 cmp -sl of a written file', 'printf %s x > "$OUT_DIR/r9"\ncmp -sl "$OUT_DIR/r9" "$OUT_DIR/author.id"'),
                        ('M11 a dot-dot-segment read after cd', 'printf %s x > "$OUT_DIR/r9"\ncd "$OUT_DIR/" && iconv ././r9'),
                        ('a [ ] class under an opaque directory', 'printf %s x > "$OUT_DIR/r9"\niconv "$1"/[$2]'),
                        ('a [ ] class after cd into an opaque directory', 'printf %s x > "$OUT_DIR/r9"\ncd "$1" && iconv [$2]'),
                        ('tar of the working directory', 'printf %s x > "$OUT_DIR/r9"\ncd "$OUT_DIR" && tar -cf - .'),
                        ('a default expansion of the root', 'printf %s x > "$OUT_DIR/r9"\niconv "${OUT_DIR:-x}/r9"'),
                        ('diff of a written file', 'printf %s x > "$OUT_DIR/r9"\ndiff "$OUT_DIR/r9" /dev/null'),
                        ('a numbered input redirect', 'printf %s x > "$OUT_DIR/r9"\niconv 0< "$OUT_DIR/r9"'),
                        ('exec that opens a written file for reading', 'printf %s x > "$OUT_DIR/r9"\nexec 3< "$OUT_DIR/r9"\niconv <&3'),
                        ('a read of a cp destination', 'printf %s x > "$OUT_DIR/r9"\ncp "$OUT_DIR/r9" "$OUT_DIR/r8"\niconv "$OUT_DIR/r8"'),
                        ('a read of an mv destination', 'printf %s x > "$OUT_DIR/r9"\nmv "$OUT_DIR/r9" "$OUT_DIR/r7"\niconv "$OUT_DIR/r7"'),
                        ('a read of an ln name', 'printf %s x > "$OUT_DIR/r9"\nln -s "$OUT_DIR/r9" "$OUT_DIR/l"\niconv "$OUT_DIR/l"'),
                        ('a read of a dd destination', 'printf %s x > "$OUT_DIR/r9"\ndd if="$OUT_DIR/r9" of="$OUT_DIR/r8" 2>/dev/null\niconv "$OUT_DIR/r8"'),
                        ('dd of a written file to stdout', 'printf %s x > "$OUT_DIR/r9"\ndd if="$OUT_DIR/r9" 2>/dev/null'),
                        ('a read of an scp download', 'scp -q h:/x "$OUT_DIR/k" >/dev/null 2>&1\niconv "$OUT_DIR/k"'),
                        ('a read of a file written at fd 2', 'bat /etc/hostname 2> "$OUT_DIR/e"\niconv "$OUT_DIR/e"'),
                        ('a read under a tilde', 'printf %s x > ~/r9\niconv ~/r9'),
                        ('a script function given a written path', 'printf %s x > "$OUT_DIR/r9"\nrd() { iconv "$1"; }\nrd "$OUT_DIR/r9"'),
                        ('an option value naming a written file', 'printf %s x > "$OUT_DIR/r9"\nopenssl enc -in"$OUT_DIR/r9"')):
        b2, _ = taint_findings(wrap(body), tainted_names(wrap(body)))
        # #5763: a root finding is no evidence for the rule a negative control names; it is not counted.
        b2 = [f for f in b2 if f not in root_findings(wrap(body))]
        probe("V1 closed-world negative control is flagged: %s" % label, len(b2) > len(bad), str(b2[len(bad):][:2]))
    # #5236: constructs a name-based scan cannot follow are not allowed in federate.sh at all.
    cb = construct_findings(fs)
    probe("V1 federate.sh uses no construct the taint scan cannot follow", not cb, " ".join(cb[:6]))
    for label, body in (("eval", 'eval "no \\"x \\$qjson\\""'), ("eval in single quotes", "eval 'no \"x $qjson\"'"),
                        ("eval of an echo", 'eval "echo \\$qjson"'), ("a here-string", 'cat <<< "$qjson"'),
                        ("a here-string to jq", 'jq . <<< "$qjson"'),
                        ("read", 'read -r t <<< "$qjson"'), ("printf -v", "printf -v t '%s' \"$qjson\""),
                        ("an indirect expansion", 'n=qjson\nno "x ${!n}"'), ("a nameref", 'declare -n r=qjson\nno "x $r"'),
                        ("mapfile", 'mapfile -t arr < "$f"'), ("tee", 'tee < "$f"'), ("source", 'source "$f"'),
                        ("a here-document in verify", 'cat <<EOF\n$qjson\nEOF'),
                        # #5359: assignment forms whose target the name-based scan cannot record.
                        ("an indexed assignment", 'arr[0]=$qjson\nno "x ${arr[0]}"'),
                        ("an indexed append assignment", 'arr[1]+=$qjson\nno "x ${arr[1]}"'),
                        ("an escaped space in an assignment", 't=x\\ $qjson\nno "x $t"'),
                        ("a default-assign expansion", ': "${t:=$qjson}"\nno "x $t"'),
                        ("a default-assign expansion without the colon", ': "${t=$qjson}"\nno "x $t"'),
                        # #5408: a backtick command substitution is refused like $( ).
                        ("a backtick substitution", 't=`printf x`'), ("a backtick substitution in a message", 'ok "x `date`"'),
                        ("a backtick substitution naming a reply", 'echo `echo $qjson`'),
                        # #5407: a process substitution runs a command the scan does not follow.
                        ("a process substitution as a redirect target", 'printf %s "$qjson" > >(cat)'),
                        ("a process substitution as a tee target", 'printf %s "$qjson" > >(cat >&2)'),
                        ("a process substitution as an input", 'cat <(printf %s "$qjson")'),
                        ("a process substitution fed to sed", 'sed p <(printf %s "$qjson")'),
                        # #5411: the error expansion prints its word.
                        ("an error expansion", ': "${t:?$qjson}"'), ("an error expansion without the colon", ': "${t?$qjson}"'),
                        # #5410: arithmetic evaluation of a reply prints it in a syntax error.
                        ("let", 'let t=qjson'), ("let with a space", 'let "t = $qjson"'),
                        ("an arithmetic command", '(( t = qjson ))'),
                        ("an arithmetic command after a keyword", 'if (( qjson )); then :; fi'),
                        ("an arithmetic for loop", 'for (( t = 0; t < qjson; t++ )); do :; done')):
        probe("V1 construct negative control is flagged: %s" % label, len(construct_findings(wrap(body))) > len(cb))
    # Accepted by design (#5236): reply_status prints only a 3-digit status or the word non-status, so a
    # reply body passed to it reaches the terminal as one of those 1001 closed values, never as its bytes.
    for label, body in (("helpers only", 'no "x $(reply_status "$qcode") ($(reply_len "$qjson"))"'),
                        ("a reply piped to grep", "echo \"$versions\" | grep -qx 'age=1.8.0'"),
                        ("a reply captured through sed", "age_ver=\"$(printf '%s\\n' \"$versions\" | sed -n 's/^age=//p')\""),
                        ("the status helper given a reply body", 'no "x $(reply_status "$qjson")"'),
                        ("a test after then", 'if true; then [ "$qjson" = x ] && :; fi'),
                        # #5409: a file read whose output is a file, a count, a status or a capture.
                        ("head into a file", 'head -c 9 "$OUT_DIR/r" > "$OUT_DIR/o"'),
                        ("head into wc", 'head -c 9 "$OUT_DIR/r" | wc -c'),
                        ("grep -q of a file", 'grep -q x "$OUT_DIR/r"'),
                        ("grep -qx of a file with stderr discarded", 'if grep -qx pat "$OUT_DIR/r" 2>/dev/null; then :; fi'),
                        ("grep -c of a file in a capture", 'k="$(LC_ALL=C grep -aEcx x "$OUT_DIR/r")"'),
                        ("head in a capture", 'k="$(head -c 9 "$OUT_DIR/r" | wc -c)"'),
                        ("sed from a file to /dev/null", 'sed -n p < "$OUT_DIR/r" > /dev/null'),
                        ("head into grep -q", 'head -c 1 -- "$OUT_DIR/r" | LC_ALL=C grep -q x'),
                        # #5413: a pipe through base64 that goes on into curl is node-bound; b64 is pinned below.
                        ("a pipe through base64 into curl", 'printf %s "$qjson" | base64 | curl -s -d @- https://x'),
                        # #5412: a plain path or /dev/null is a file whatever the order of the other redirects.
                        ("a write to a file", 'printf %s "$qjson" > "$OUT_DIR/r"'),
                        ("an append to a file", 'printf %s "$qjson" >> "$OUT_DIR/r"'),
                        ("a write to /dev/null", 'printf %s "$qjson" > /dev/null'),
                        ("a file and stderr to the file", 'printf %s "$qjson" >"$OUT_DIR/r" 2>&1'),
                        ("stderr to the terminal, then a file", 'printf %s "$qjson" 2>&1 >"$OUT_DIR/r"'),
                        ("an &> to a file", 'printf %s "$qjson" &>"$OUT_DIR/r"'),
                        ("a dup to stderr, then a file", 'printf %s "$qjson" >&2 >"$OUT_DIR/r"'),
                        # #5418: the "$VAR/literal" form stays a file, and the silent file commands are not readers.
                        ("a file with a variable suffix", 'printf %s "$qjson" > "$OUT_DIR/r$n"'),
                        ("a file under a braced variable", 'printf %s "$qjson" > "${OUT_DIR}/r.txt"'),
                        ("rm of a written file", 'printf %s x > "$OUT_DIR/r9"\nrm -f -- "$OUT_DIR/r9"'),
                        ("scp of a written file", 'printf %s x > "$OUT_DIR/r9"\nscp -q "$OUT_DIR/r9" h:/x >/dev/null 2>&1'),
                        ("mv of a written file", 'printf %s x > "$OUT_DIR/r9"\nmv -f -- "$OUT_DIR/r9" "$OUT_DIR/r8"'),
                        ("a reader that writes to a file", 'printf %s x > "$OUT_DIR/r9"\nbat "$OUT_DIR/r9" > "$OUT_DIR/o"'),
                        ("a reader of an unrelated path", 'bat /etc/hostname'),
                        # Pins for the unlisted-reader check: each control differs from a flagged form in one point.
                        ("a listed printer into a silent consumer", 'printf %s x > "$OUT_DIR/r9"\nhead -c 1 -- "$OUT_DIR/r9" | LC_ALL=C grep -q x'),
                        ("printf of a written file path", 'printf %s x > "$OUT_DIR/r9"\nprintf \'%s\\n\' "$OUT_DIR/r9"'),
                        ("a file with a variable inside a segment", 'printf %s "$qjson" > "$OUT_DIR/a$n.txt"'),
                        ("a literal file whose name starts with dots", 'printf %s "$qjson" > "$OUT_DIR/..hidden"'),
                        ("cp of a written file to a file", 'printf %s x > "$OUT_DIR/r9"\ncp -f -- "$OUT_DIR/r9" "$OUT_DIR/r8"'),
                        ("install of a written file to a file", 'printf %s x > "$OUT_DIR/r9"\ninstall -m 0600 "$OUT_DIR/r9" "$run_dir/client.crt"'),
                        ("cp of a written file to /dev/null", 'printf %s x > "$OUT_DIR/r9"\ncp "$OUT_DIR/r9" /dev/null'),
                        ("cmp -s of a written file", 'printf %s x > "$OUT_DIR/r9"\ncmp -s "$OUT_DIR/r9" "$OUT_DIR/author.id"'),
                        ("cmp of a written file", 'printf %s x > "$OUT_DIR/r9"\ncmp "$OUT_DIR/r9" "$OUT_DIR/author.id" >/dev/null'),
                        ("ln of a written file", 'printf %s x > "$OUT_DIR/r9"\nln -sf "$OUT_DIR/r9" "$OUT_DIR/r8"'),
                        ("a listed printer of a braced written path", 'printf %s x > "$OUT_DIR/r9"\nhead -c 1 -- "${OUT_DIR}/r9" | LC_ALL=C grep -q x'),
                        ("a reader of another literal path", 'printf %s x > /var/tmp/r9\niconv /var/tmp/r90'),
                        ("a read of a different name after cd", 'printf %s x > "$OUT_DIR/r9"\ncd "$OUT_DIR" && iconv r90'),
                        ("a file under a nested directory", 'printf %s "$qjson" > "$OUT_DIR/sub/r.txt"'),
                        ("a reader with only stderr sent to a written file", 'printf %s x > "$OUT_DIR/r9"\nbat /etc/hostname 2> "$OUT_DIR/r9"'),
                        ("a here-document to a file", 'cat > "$OUT_DIR/r" <<EOT\nx $qjson\nEOT'),
                        # #5406: a reply is a VALUE of a declaration, or reaches a filter on stdin: both print nothing.
                        ("arithmetic on a counter", 'c=$((c + 1))\n[ "$c" -gt 3 ] && :'),
                        ("a constant substring of a reply", 'x="${qjson:0:8}"'),
                        ("local with the reply as a value", 'local v="$qjson"'),
                        ("export with the reply as a value", 'export v="$qjson"'),
                        ("readonly with the reply as a value", 'readonly v=$qjson'),
                        ("a filter fed the reply on stdin", "nb=\"$(printf '%s' \"$qjson\" | tr -d x | wc -c)\""),
                        ("a test after elif, else and while", 'if false; then :; elif [ "$qjson" = x ]; then :; else [[ "$qjson" == y ]]; fi\nwhile [ "$qjson" = z ]; do :; done'),
                        # #5602: proven file targets stay files.
                        ("a write under a nested proven path", 'printf %s "$qjson" > "$OUT_DIR/peers/r"'),
                        ("a write through a variable holding a proven path", 'f="$OUT_DIR/r9"\nprintf %s "$qjson" > "$f"'),
                        ("a write to a dated name", 'printf %s "$qjson" > "$OUT_DIR/r.$(date -u +%Y%m%d)"'),
                        ("a write to a mktemp name under a root", 'k="$(mktemp -u "$run_dir/.k.XXXXXXXX")"\nprintf %s "$qjson" > "$k"'),
                        ("an scp download to a proven file", 'scp -q h:/x "$OUT_DIR/r9" >/dev/null 2>&1'),
                        ("an scp download named by the checked identity array", 'scp -q h:/x "$OUT_DIR/${FED_IDS[0]}.pub"'),
                        ("install -d of the run directory", 'install -d -m 0700 "$run_dir"'),
                        ("install -D to a proven nested file", 'printf %s x > "$OUT_DIR/r9"\ninstall -D -m 0600 "$OUT_DIR/r9" "$run_dir/sub/r"'),
                        ("cp -t into a proven directory", 'printf %s x > "$OUT_DIR/r9"\ncp -t "$run_dir" "$OUT_DIR/r9"'),
                        ("dd of a written file to a proven file", 'printf %s x > "$OUT_DIR/r9"\ndd if="$OUT_DIR/r9" of="$OUT_DIR/r8" 2>/dev/null'),
                        ("a trap that removes a written file", 'printf %s x > "$OUT_DIR/r9"\ntrap \'rm -f -- "$OUT_DIR/r9"; exit 130\' INT'),
                        ("exec that opens a proven file", 'exec 8> "$OUT_DIR/r9"'),
                        # #5621: commands that name a written file and print nothing of it, and reads of other files.
                        ('rm of a written file', 'printf %s x > "$OUT_DIR/r9"\nrm -f -- "$OUT_DIR/r9"'),
                        ('a reader whose output is a proven file', 'printf %s x > "$OUT_DIR/r9"\niconv "$OUT_DIR/r9" > "$OUT_DIR/o"'),
                        ('chmod of a written file', 'printf %s x > "$OUT_DIR/r9"\nchmod 600 "$OUT_DIR/r9"'),
                        ('a test of a written file', 'printf %s x > "$OUT_DIR/r9"\n[ -s "$OUT_DIR/r9" ] && :'),
                        ('a count of a written file in a capture', 'printf %s x > "$OUT_DIR/r9"\nk="$(wc -c < "$OUT_DIR/r9")"'),
                        ('grep -c of a written file in a capture', 'printf %s x > "$OUT_DIR/r9"\nk="$(grep -c x "$OUT_DIR/r9")"'),
                        ('a read of a file the script does not write', 'printf %s x > "$OUT_DIR/r9"\niconv /etc/hostname'),
                        ('a read of a near name', 'printf %s x > "$OUT_DIR/r9"\niconv "$OUT_DIR/r90"'),
                        ('a capture that reads no file', 'printf %s x > "$OUT_DIR/r9"\nt="$(date -u +%s)"'),
                        ('a declaration of a written path', 'printf %s x > "$OUT_DIR/r9"\nlocal v="$OUT_DIR/r9"'),
                        ('a subshell rm after cd', 'printf %s x > "$OUT_DIR/r9"\n(cd "$OUT_DIR" && rm -f r9)'),
                        ('pushd and popd around an rm', 'printf %s x > "$OUT_DIR/r9"\npushd "$OUT_DIR" >/dev/null && rm -f r9 && popd >/dev/null'),
                        ('a while read loop over another file', 'printf %s x > "$OUT_DIR/r9"\nwhile read -r l; do :; done < /etc/hostname'),
                        ('exec that opens a proven file for writing', 'exec 8> "$OUT_DIR/r9"\nprintf x >&8')):
        # #5763: run_dir is proven only inside loadgen, after its assignment; a control under it runs there.
        text = in_loadgen(body) if "$run_dir" in body else wrap(body)
        b2, _ = taint_findings(text, tainted_names(text))
        probe("V1 closed-world control is accepted: %s" % label, len(b2) == len(bad), str(b2[len(bad):][:2]))


def n1_no_locale_ranges():
    guards = [l for l in (TPL.read_text() + FED.read_text()).splitlines() if "{64}" in l and "=~" in l]
    probe("N1 four key guards found", len(guards) == 4, str(len(guards)))
    for g in guards:
        probe("N1 guard has no locale-dependent range: " + g.strip()[:60], re.search(r"\[[^\]]*\w-\w[^\]]*\]", g) is None)
    # Every bash =~ check in the three shipped shell surfaces (the key guards, the node_get id
    # check, the spawn.sh URL check, the #5602 fed_identity check): a range matches non-ASCII code points under
    # UTF-8 locales.
    allre = [l for l in (TPL.read_text() + FED.read_text() + SPAWN.read_text()).splitlines() if "=~" in l and not l.lstrip().startswith("#")]
    probe("N1 eight =~ checks found", len(allre) == 8, str(len(allre)))
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
        # #5238: an accepted write (201 or 202) whose memory id is not a plain id is one FAIL with one cause:
        # no PASS line may precede the refused-id FAIL, and the id is never read back.
        for name, snip, cv, jv, idv, _ in sites:
            for code in ("201", "202"):
                sc = ("set -u\n%s\nok() { echo \"OK $*\"; }\nno() { echo \"NO $*\"; }\n"
                      "node_get() { : > %s; echo '{\"id\":\"abc\",\"metadata\":{\"attest_level\":\"agent_attested\"}}'; }\n"
                      "sleep() { :; }\n%s='%s'\n%s='{}'\nQID=''\nSID=''\n%s='a b'\n%s\n"
                      % (defs, d / "called", cv, code, jv, idv, snip))
                (d / "called").unlink() if (d / "called").exists() else None
                r = run_bash(sc, d)
                oks = sum(1 for l in r.stdout.splitlines() if l.startswith("OK"))
                nos = sum(1 for l in r.stdout.splitlines() if l.startswith("NO"))
                called = 1 if (d / "called").exists() else 0
                probe("#5238 %s write accepted with %s and a non-plain memory id: 1 FAIL, 0 PASS, no readback" % (name, code),
                      bool(snip) and r.returncode == 0 and nos == 1 and oks == 0 and called == 0
                      and "not a plain id" in r.stdout,
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


FUNC_DEF = re.compile(r"^(\s*)(?:function\s+(\w+)(?:\s*\(\s*\))?|(\w+)\s*\(\s*\))\s*(\{.*)?$")


def heredoc_ops(line):
    """#5655: (delimiter, quoted, strip_tabs) of every here-document operator of one logical line, in order.
    An operator counts outside single quotes and outside double quotes (a $( ) capture inside double quotes opens
    a fresh context), never inside $(( )) arithmetic, and never as <<< (a here-string). Any quote or backslash in
    the delimiter word makes the body literal; <<- strips leading tabs from the body and the terminator."""
    ops, stack, i = [], [["top", 0]], 0   # context and its open parenthesis depth
    while i < len(line):
        c, top = line[i], stack[-1]
        ctx = top[0]
        if ctx == "ar":
            if c == "(":
                top[1] += 1
            elif c == ")" and top[1]:
                top[1] -= 1
            elif line.startswith("))", i):
                stack.pop()
                i += 1
            i += 1
            continue
        if c == "\\":
            i += 2
            continue
        if line.startswith("$((", i):
            stack.append(["ar", 0])
            i += 3
            continue
        if line.startswith("$(", i):
            stack.append(["cs", 0])
            i += 2
            continue
        if ctx == "dq":
            if c == '"':
                stack.pop()
            i += 1
            continue
        if c == "'":
            j = line.find("'", i + 1)
            i = len(line) if j < 0 else j + 1
            continue
        if c == "#" and (i == 0 or line[i - 1] in " \t;&|("):
            break   # a comment: the rest of the line is no code
        if c == '"':
            stack.append(["dq", 0])
        elif c == "(" and ctx == "cs":
            top[1] += 1
        elif c == ")" and ctx == "cs":
            if top[1]:
                top[1] -= 1
            else:
                stack.pop()
        elif line.startswith("<<", i) and not line.startswith("<<<", i) and line[i - 1:i] != "<":
            j = i + 2
            strip = line[j:j + 1] == "-"
            j += 1 if strip else 0
            while j < len(line) and line[j] in " \t":
                j += 1
            word = ""
            while j < len(line) and line[j] not in " \t;&|<>()":
                if line[j] in "'\"":
                    k = line.find(line[j], j + 1)
                    k = len(line) - 1 if k < 0 else k
                    word += line[j:k + 1]
                    j = k + 1
                else:
                    word += line[j:j + 2] if line[j] == "\\" else line[j]
                    j += 2 if line[j] == "\\" else 1
            if word:
                ops.append((re.sub(r"[\\'\"]", "", word), bool(re.search(r"[\\'\"]", word)), strip))
            i = j
            continue
        i += 1
    return ops


_HEREDOC_CACHE = {}


def heredoc_scan(text):
    """#5655: ({body line number: (delimiter, quoted, operator line)}, [(operator line, delimiter)] unterminated,
    {terminator line numbers}).
    Bodies follow the logical line that opens them, one after another when a line opens several. A body whose
    terminator never comes is not a body: bash would read the rest of the script as text, so the scan reads it
    as code and reports the operator, rather than hide every following line."""
    if text in _HEREDOC_CACHE:
        return _HEREDOC_CACHE[text]
    lines = text.splitlines()
    body, open_, ends, buf, n = {}, [], set(), "", 0
    while n < len(lines):
        raw = lines[n]
        n += 1
        if not buf and raw.lstrip().startswith("#"):
            continue
        buf += raw[:-1] + " " if raw.endswith("\\") else raw
        if raw.endswith("\\"):
            continue
        at, ops, buf = n, heredoc_ops(buf), ""
        for delim, quoted, strip in ops:
            end = next((k for k in range(n, len(lines))
                        if (lines[k].lstrip("\t") if strip else lines[k]) == delim), None)
            if end is None:
                open_.append((at, delim))
                break
            for k in range(n, end):
                body[k + 1] = (delim, quoted, at)
            ends.add(end + 1)
            n = end + 1
    _HEREDOC_CACHE[text] = (body, open_, ends)
    return body, open_, ends


def heredoc_body_lines(text):
    """#5655: (line number, text, quoted, operator line) of every here-document body line."""
    body = heredoc_scan(text)[0]
    lines = text.splitlines()
    return [(k, lines[k - 1], q, at) for k, (_, q, at) in sorted(body.items())]


def logical_lines(text):
    """(first line number, joined text, enclosing function) per logical line, outside heredoc bodies and comments.
    #5414: a function is recorded in every spelling (name() {, name () {, function name {, function name() {,
    a brace on the next line), indented or not; a one-line definition names only its own line; a multi-line one
    is open until a closing brace at its own indent."""
    out, buf, start = [], "", 0
    body, _, ends = heredoc_scan(text)   # #5655: every operator of a line, <<- tabs, quoted delimiters, never <<<
    stack, pending = [], None   # open functions (name, indent); a definition whose brace has not opened yet
    for n, raw in enumerate(text.splitlines(), 1):
        if n in body or n in ends:
            continue
        if not buf and raw.lstrip().startswith("#"):
            continue
        d = FUNC_DEF.match(raw) if not buf else None
        name = d and (d.group(2) or d.group(3))
        rest = (d.group(4) or "") if d else ""
        oneliner = bool(name) and rest.startswith("{") and rest.rstrip().endswith("}") and not raw.endswith("\\")
        if name and not oneliner:
            pending = (name, len(d.group(1)))
            if rest.startswith("{"):
                stack.append(pending)
                pending = None
        elif pending and raw.strip().startswith("{") and not buf:
            stack.append(pending)
            pending = None
        if not buf:
            start = n
        buf += raw[:-1] + " " if raw.endswith("\\") else raw
        if raw.endswith("\\"):
            continue
        func = name if oneliner else (name or (pending[0] if pending else (stack[-1][0] if stack else "")))
        out.append((start, buf, func))
        if stack and raw.lstrip().startswith("}") and len(raw) - len(raw.lstrip()) == stack[-1][1] and not (name and not oneliner):
            stack.pop()
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


SSH_CALL = re.compile(r"(?<![\w$/.-])(ssh|scp)(?![\w-])")


def ssh_batch_findings(text):
    """#5274: every ssh/scp call passes $SSH_BATCH as its first argument, so no override can drop it."""
    bad = []
    for n, line, _ in logical_lines(text):
        code = strip_messages(line)
        for m in SSH_CALL.finditer(code):
            if not re.match(r"\s+\$SSH_BATCH\s", code[m.end():]):
                bad.append("%d:%s" % (n, m.group(1)))
    # #5655: a here-document body is a script some shell runs; no body line may name ssh or scp at all.
    for k, raw, _, _ in heredoc_body_lines(text):
        for m in SSH_CALL.finditer(raw):
            bad.append("%d:%s in a here-document" % (k, m.group(1)))
    return bad


def first_batchmode(args):
    """The BatchMode value ssh/scp would use: the first one given on the command line (ssh_config(5))."""
    i = 0
    while i < len(args):
        a = args[i]
        if a == "-o" and i + 1 < len(args):
            v, i = args[i + 1], i + 2
        elif a.startswith("-o") and len(a) > 2:
            v, i = a[2:], i + 1
        else:
            i += 1
            continue
        k = re.split(r"[=\s]+", v.strip(), 1)
        if k[0].lower() == "batchmode":
            return k[1].strip().lower() if len(k) > 1 else ""
    return None


def ssh_batch_5274():
    """#5274: a node cannot raise an interactive ssh prompt on the operator's terminal or hang the run."""
    fs = FED.read_text()
    bad = ssh_batch_findings(fs)
    probe("#5274 every ssh and scp call in federate.sh passes $SSH_BATCH first", not bad, " ".join(bad[:12]))
    lines = [(l, f) for _, l, f in logical_lines(fs) if SSH_CALL.search(strip_messages(l))]
    probe("#5274 the ssh/scp check sees the 10 call sites (not vacuous)", len(lines) == 10, str(len(lines)))
    # #5655: the census also reads every here-document body, and none of the 7 bodies names ssh or scp.
    bodies = heredoc_body_lines(fs)
    probe("#5655 the census reads the 7 here-document bodies of federate.sh (not vacuous)",
          len({at for _, _, _, at in bodies}) == 7 and len(bodies) >= 20 and not heredoc_scan(fs)[1],
          "%d bodies, %d lines" % (len({at for _, _, _, at in bodies}), len(bodies)))
    probe("#5655 no here-document body in federate.sh names ssh or scp",
          not [k for k, raw, _, _ in bodies if SSH_CALL.search(raw)])
    assigns = "\n".join(l for l in fs.splitlines() if re.match(r"^SSH_\w+=", l))
    pre = ('%s\nSSH_USER=root\nOUT_DIR=o\nFED_DIR=/f\nn=1\nhost=h\npub=p\nj=0\nFED_IDS=(a)\nPUBLIC_IPS=(h)\n'
           'die() { echo "DIE $*"; }\n' % assigns)
    env0 = {k: v for k, v in os.environ.items() if k not in ("SSH_OPTS", "SSH_BATCH")}
    override = {"SSH_OPTS": "-o BatchMode=no -o StrictHostKeyChecking=yes", "SSH_BATCH": "-o BatchMode=no"}
    with tempfile.TemporaryDirectory(dir=str(ROOT / ".local-runs")) as t:
        d = pathlib.Path(t)
        stub_dir(d, "ssh")
        stub_dir(d, "scp")
        for label, extra in (("default SSH_OPTS", {}), ("SSH_OPTS and SSH_BATCH overridden with BatchMode=no", override)):
            got = []
            for line, _ in lines:
                prog = SSH_CALL.search(strip_messages(line)).group(1)
                call = line
                if CHANNEL_DEFS.match(line):
                    call = line + "\n%s </dev/null" % ("on_node h true" if line.startswith("on_node") else "node_sh 0")
                for f in d.glob("*.argv"):
                    f.unlink()
                env = dict(env0, PATH=str(d) + os.pathsep + env0["PATH"], LOGDIR=str(d), **extra)
                r = subprocess.run(["bash", "-c", pre + call], capture_output=True, text=True, env=env,
                                   stdin=subprocess.DEVNULL)
                argv = (d / (prog + ".argv")).read_text().splitlines() if (d / (prog + ".argv")).exists() else []
                if first_batchmode(argv) != "yes" or "DIE" in r.stdout:
                    got.append("%s:%r" % (prog, first_batchmode(argv)))
            probe("#5274 every ssh/scp call runs with BatchMode=yes in force (%s)" % label, bool(lines) and not got,
                  " ".join(got[:6]))
    for label, snippet in (("an scp with SSH_OPTS only", 'scp $SSH_OPTS -q a "$h:/x" >/dev/null 2>&1'),
                           ("an ssh with BatchMode=no ahead of SSH_BATCH", 'ssh -o BatchMode=no $SSH_BATCH h true'),
                           ("an on_node definition without SSH_BATCH", 'on_node() { ssh $SSH_OPTS "${SSH_USER}@$1" "$2"; }')):
        probe("#5274 negative control is flagged: %s" % label, bool(ssh_batch_findings(snippet + "\n")))
    probe("#5274 control is accepted: an scp with SSH_BATCH first",
          not ssh_batch_findings('scp $SSH_BATCH $SSH_OPTS -q a "$h:/x" >/dev/null 2>&1 || die "scp failed"\n'))
    probe("#5274 the BatchMode parser takes the first value given", first_batchmode(["-oBatchMode yes", "-o", "BatchMode=no"]) == "yes"
          and first_batchmode(["-o", "batchmode=No", "-o", "BatchMode=yes"]) == "no" and first_batchmode(["-q"]) is None)


def file_roots_5763():
    """#5763: OUT_DIR and run_dir are file roots only while the scan proves their value. A write under a root that
    any spelling reassigns is a finding on the write line, and the spelling is reported on its own line."""
    fs = FED.read_text()
    probe("#5763 the real federate.sh proves every root (positive control)", root_findings(fs) == [],
          " ".join(root_findings(fs)[:4]))
    W, R = 'printf %s "$qjson" > "$OUT_DIR/stdout"', 'printf %s "$qjson" > "$run_dir/stdout"'
    head = fs + "\nprobe_fn() {\n"
    first = head.count("\n") + 1
    names = tainted_names(fs)
    ROOT_NAMES = {"roots"} | {d[0] for d in ROOT_DEFS}
    for label, body, write_at in (
            ("a plain reassignment", "OUT_DIR=/dev\n" + W, 1),
            ("a local", "local OUT_DIR=/dev\n" + W, 1),
            ("a run_dir reassignment", "run_dir=/dev\n" + R, 1),
            ("a cp under a reassigned root", 'OUT_DIR=/dev\ncp "$run_dir/x" "$OUT_DIR/stdout"', 1),
            ("declare", "declare OUT_DIR=/dev\n" + W, 1), ("export", "export OUT_DIR=/dev\n" + W, 1),
            ("readonly", "readonly OUT_DIR=/dev\n" + W, 1), ("typeset", "typeset OUT_DIR=/dev\n" + W, 1),
            ("declare -g", "declare -g OUT_DIR=/dev\n" + W, 1), ("a local without a value", "local OUT_DIR\n" + W, 1),
            ("unset", "unset OUT_DIR\n" + W, 1), ("export -n", "export -n OUT_DIR\n" + W, 1),
            ("printf -v", "printf -v OUT_DIR %s /dev\n" + W, 1), ("read", "read -r OUT_DIR <<< /dev\n" + W, 1),
            ("mapfile", 'mapfile -t OUT_DIR < "$run_dir/x"\n' + W, 1), ("getopts", "getopts a: OUT_DIR\n" + W, 1),
            ("eval", "eval OUT_DIR=/dev\n" + W, 1), ("a nameref", "declare -n r=OUT_DIR\nr=/dev\n" + W, 2),
            ("a for variable", "for OUT_DIR in /dev; do\n" + W + "\ndone", 1),
            ("a select variable", "select OUT_DIR in /dev; do\n" + W + "\ndone", 1),
            ("source", 'source "$run_dir/env"\n' + W, 1), ("the dot builtin", '. "$run_dir/env"\n' + W, 1),
            ("a default assignment", ': "${OUT_DIR:=/dev}"\n' + W, 1), ("an append", "OUT_DIR+=/x\n" + W, 1),
            ("an array", "OUT_DIR=(/dev)\n" + W, 1), ("an indexed assignment", "OUT_DIR[0]=/dev\n" + W, 1),
            ("an arithmetic assignment", "(( OUT_DIR = 1 ))\n" + W, 1), ("let", "let OUT_DIR=1\n" + W, 1)):
        text = head + body + "\n}\n"
        bad, _ = taint_findings(text, names)
        roots = root_findings(text)
        probe("#5763 a write under a root after %s is a finding on the write line" % label,
              any(b.startswith("%d:" % (first + write_at)) and b.split(":")[1] not in ROOT_NAMES for b in bad),
              " ".join(b for b in bad if b.startswith("%d:" % (first + write_at))))
        probe("#5763 %s is reported on a named line" % label,
              any(re.match(r"%d:\w+:" % first, r) for r in roots), " ".join(roots[:2]))
    D = 'OUT_DIR="${OUT_DIR:-${HERE}/crypto/out}"'
    RD = 'run_dir="$REPO_ROOT/.local-runs/do-hive-runs/$(date -u +%Y-%m-%dT%H-%M-%SZ)/loadgen"'
    at, rat = fs[:fs.index(D)].count("\n") + 1, fs[:fs.index(RD)].count("\n") + 1
    for label, text, want in (
            ("an if around the assignment", fs.replace(D, 'if [ -n "${X:-}" ]; then\n' + D + "\nfi"),
             "%d:OUT_DIR:assignment is not unconditional in its scope" % (at + 1)),
            ("an && chain into the assignment", fs.replace(D, "true &&\n" + D),
             "%d:OUT_DIR:assignment is not unconditional in its scope" % (at + 1)),
            ("a group around the assignment", fs.replace(D, "{\n" + D + "\n}"),
             "%d:OUT_DIR:assignment is not unconditional in its scope" % (at + 1)),
            ("a loop around the assignment", fs.replace(D, "while false; do\n" + D + "\ndone"),
             "%d:OUT_DIR:assignment is not unconditional in its scope" % (at + 1)),
            ("a case before the assignment", fs.replace(D, "case x in x) : ;; esac\n" + D),
             "%d:OUT_DIR:a case, subshell or function definition before its assignment" % at),
            ("a subshell before the assignment", fs.replace(D, "( : )\n" + D),
             "%d:OUT_DIR:a case, subshell or function definition before its assignment" % at),
            ("an || on the assignment line", fs.replace(D, "false || " + D),
             "%d:OUT_DIR:named outside its one reviewed assignment" % at),
            ("a read before the assignment", fs.replace(D, ': "${OUT_DIR}"\n' + D),
             "%d:OUT_DIR:read before its assignment or outside its function" % at),
            ("a second reviewed assignment", fs + D + "\n",
             "%d:OUT_DIR:2 reviewed assignments, not one" % (fs.count("\n") + 1)),
            ("run_dir assigned in an if", fs.replace(RD, "if true; then\n" + RD + "\nfi"),
             "%d:run_dir:assignment is not unconditional in its scope" % (rat + 1)),
            ("run_dir read in another function", head + ': "$run_dir"\n}\n',
             "%d:run_dir:read before its assignment or outside its function" % first),
            ("HERE reassigned", head + "HERE=/dev\n}\n", "%d:HERE:named outside its one reviewed assignment" % first),
            ("REPO_ROOT reassigned", head + "REPO_ROOT=/\n}\n",
             "%d:REPO_ROOT:named outside its one reviewed assignment" % first),
            ("a pass-through that changes the value", head + 'OUT_DIR="$OUT_DIR/x" true\n}\n',
             "%d:OUT_DIR:named outside its one reviewed assignment" % first),
            ("a computed trap action", head + 'trap "$X" EXIT\n}\n', "%d:roots:computed trap action" % first),
            ("a computed command word", head + '"$c" OUT_DIR\n}\n', '%d:roots:computed command "$c"' % first),
            ("a computed declarator name", head + 'declare "$n=/dev"\n}\n', "%d:roots:computed name" % first),
            ("a computed unset name", head + 'unset "$n"\n}\n', "%d:roots:computed name" % first),
            ("local -n", head + "local -n r=OUT_DIR\n}\n", "%d:roots:nameref" % first),
            ("wait -p with a computed name", head + 'wait -n -p "$n"\n}\n', "%d:roots:computed operand of wait" % first),
            ("readarray with a computed name", head + 'readarray "$n" < x\n}\n',
             "%d:roots:computed operand of readarray" % first),
            ("read with a quoted name", head + 'read -r "O"UT_DIR <<< /dev\n}\n', "%d:roots:computed operand of read" % first),
            ("an escaped read with a computed name", head + '\\read -r "$n"\n}\n',
             "%d:roots:computed operand of read" % first),
            ("command read with a computed name", head + 'command read -r "$n"\n}\n',
             "%d:roots:computed operand of read" % first),
            ("printf -v with a computed name", head + 'printf -v "$n" %s /dev\n}\n',
             "%d:roots:computed operand of printf" % first),
            ("mapfile with a computed name", head + 'mapfile -t "$n" < x\n}\n', "%d:roots:computed operand of mapfile" % first),
            ("getopts with a computed name", head + 'getopts a: "$n"\n}\n', "%d:roots:computed operand of getopts" % first),
            ("an escaped OUT_DIR assignment through declare", head + 'declare O\\UT_DIR=/dev\n}\n',
             "%d:roots:computed name" % first),
            ("an alias", head + "alias x=y\n}\n", "%d:roots:alias" % first),
            ("eval of a string that names no root", head + 'eval "$cmd"\n}\n', "%d:roots:eval" % first),
            ("source of a literal file", head + "source ./env\n}\n", "%d:roots:source" % first),
            ("the dot builtin on a literal file", head + ". ./env\n}\n", "%d:roots:source" % first),
            ("the assignment moved into a function", fs.replace(D, "mv_fn() {\n" + D + "\n}"),
             "0:OUT_DIR:0 reviewed assignments, not one"),
            ("an || chain into the assignment", fs.replace(D, "false ||\n" + D),
             "%d:OUT_DIR:assignment is not unconditional in its scope" % (at + 1)),
            ("a pipe into the assignment", fs.replace(D, "true |\n" + D),
             "%d:OUT_DIR:assignment is not unconditional in its scope" % (at + 1)),
            ("a subshell opened on its own line around the assignment", fs.replace(D, "(\n" + D + "\n)"),
             "%d:OUT_DIR:a case, subshell or function definition before its assignment" % at),
            ("a same-value pass-through into a declarator", head + 'OUT_DIR="$OUT_DIR" local y\n}\n',
             "%d:OUT_DIR:named outside its one reviewed assignment" % first),
            ("a bare same-value assignment", head + 'OUT_DIR="$OUT_DIR"\n}\n',
             "%d:OUT_DIR:named outside its one reviewed assignment" % first)):
        roots = root_findings(text)
        probe("#5763 %s is reported as %s" % (label, want), want in roots, " ".join(roots[:4]))
        probe("#5763 %s leaves a root target the terminal" % label,
              target_kind('"$OUT_DIR/a"', text) == "terminal", target_kind('"$OUT_DIR/a"', text))
    for label, text in (("a same-value pass-through", head + 'OUT_DIR="$OUT_DIR" true\n}\n'),
                        ("a literal trap action", head + "trap 'rm -f x' EXIT\n}\n"),
                        ("a cd into the root", head + 'cd "$OUT_DIR"\n}\n'),
                        ("a read of a literal name from a root file", head + 'read -r l < "$OUT_DIR/x"\n}\n'),
                        ("a read of a literal name from a here-string", head + 'read -r l <<< "$x"\n}\n'),
                        ("printf -v to a literal name", head + "printf -v x %s y\n}\n")):
        probe("#5763 %s keeps every root proven" % label, root_findings(text) == [], " ".join(root_findings(text)))
        probe("#5763 %s keeps a target under OUT_DIR a file" % label,
              target_kind('"$OUT_DIR/a"', text) == "file", target_kind('"$OUT_DIR/a"', text))


def heredoc_5655():
    """#5655: here-document bodies are read: an ssh or scp in a body is a finding, a <<- body ends at its
    tab-indented terminator, every operator of a line counts in any delimiter spelling, <<< and $(( << )) are no
    operator, and an unterminated body is read as code. The #5274 comment states the rule and is pinned."""
    fs = FED.read_text()
    m = re.search(r"((?:^#.*\n)+)SSH_BATCH=\"-o BatchMode=yes\"\n", fs, re.M)
    block = m.group(1) if m else ""
    probe("#5655 the #5274 comment above SSH_BATCH states the rule and the here-document case",
          "#5274: every ssh and scp call passes SSH_BATCH first" in block
          and "ssh uses the first value given for an\n# option, so no SSH_OPTS override can turn batch mode off" in block
          and "No here-document body runs ssh or scp (#5655)" in block, block[-200:])
    B = "$SSH_BATCH"
    for label, snip in (
            ("an ssh in an unquoted node_sh body", "node_sh 0 <<EOS >/dev/null 2>&1\nssh h true\nEOS"),
            ("an ssh with SSH_BATCH in a quoted body", "node_sh 0 <<'EOS' >/dev/null 2>&1\nssh %s h true\nEOS" % B),
            ("an scp in a body", "node_sh 0 <<'EOS' >/dev/null 2>&1\nscp %s a h:/b\nEOS" % B),
            ("an ssh with SSH_BATCH in a double-quoted delimiter body", 'node_sh 0 <<"EOS" >/dev/null 2>&1\nssh %s h true\nEOS' % B),
            ("an ssh with SSH_BATCH in a backslash delimiter body", "node_sh 0 <<\\EOS >/dev/null 2>&1\nssh %s h true\nEOS" % B),
            ("an ssh with SSH_BATCH in a split-quote delimiter body", 'node_sh 0 <<E"O"S >/dev/null 2>&1\nssh %s h true\nEOS' % B),
            ("an ssh in a <<- body", "node_sh 0 <<-EOS >/dev/null 2>&1\n\tssh %s h true\n\tEOS" % B),
            ("an ssh after a <<- body with a tab terminator", "node_sh 0 <<-EOS >/dev/null 2>&1\n\ttrue\n\tEOS\nssh h true"),
            ("an ssh after a here-string read as an operator", "x=$(cat <<<EOS)\nssh h true\nEOS"),
            ("an ssh after an arithmetic shift", "x=$((1<<y))\nssh h true\ny"),
            ("an ssh after a here-document word in a comment", "true # <<E\nssh h true\nE"),
            ("an ssh in the second body of a line", "node_sh 0 <<A <<B >/dev/null 2>&1\na\nA\nssh %s h true\nB" % B),
            ("an ssh after a terminator with a trailing space", "node_sh 0 <<EOS >/dev/null 2>&1\ntrue\nEOS \nssh h true"),
            ("an ssh in a capture in an unquoted body", "node_sh 0 <<EOS >/dev/null 2>&1\necho \\$(ssh %s h id)\nEOS" % B),
            ("an scp in a body inside a capture", "v=\"$(node_sh 0 <<'EOS' 2>/dev/null\nscp %s a h:/b\nEOS\n)\"" % B),
            ("an indented ssh in a body", "node_sh 0 <<'EOS' >/dev/null 2>&1\n    ssh %s h true\nEOS" % B),
            ("an ssh after an empty delimiter body", "node_sh 0 <<'' >/dev/null 2>&1\ntrue\n\nssh h true"),
            ("an ssh after a body opened in a continued line", "node_sh 0 \\\n  <<-EOS >/dev/null 2>&1\n\ttrue\n\tEOS\nssh h true"),
            ('an ssh with SSH_BATCH in a body whose word follows a blank', "node_sh 0 << 'EOS' >/dev/null 2>&1\nssh %s h true\nEOS" % B),
            ('an ssh with SSH_BATCH in a body whose word touches a redirect', "node_sh 0 <<'EOS'>/dev/null 2>&1\nssh %s h true\nEOS" % B),
            ('an ssh with SSH_BATCH in a body opened after a closed capture', 'v="$(true)"; node_sh 0 <<\'EOS\' >/dev/null 2>&1\nssh %s h true\nEOS' % B),
            ('an ssh with SSH_BATCH in a body opened after a closed arithmetic expansion', "n=$((1 + 1)); node_sh 0 <<'EOS' >/dev/null 2>&1\nssh %s h true\nEOS" % B),
            ('an ssh with SSH_BATCH in a body opened after an escaped quote', 'echo \\"; node_sh 0 <<\'EOS\' >/dev/null 2>&1\nssh %s h true\nEOS' % B)):
        probe("#5655 ssh census negative control is flagged: %s" % label, bool(ssh_batch_findings(snip + "\n")),
              str(ssh_batch_findings(snip + "\n")))
    wrap = lambda body: fs + "\nprobe_fn() {\n%s\n}\n" % body
    cb = construct_findings(fs)
    for label, body in (
            ("a double-quoted delimiter here-document to cat", 'cat <<"EOF"\nx\nEOF'),
            ("a backslash delimiter here-document to cat", "cat <<\\EOF\nx\nEOF"),
            ("a quoted here-document to cat", "cat <<'EOF'\nx\nEOF"),
            ("a <<- here-document to cat", "cat <<-EOF\n\tx $qjson\n\tEOF"),
            ("a here-document to cat after a node_sh operator", "node_sh 0 <<A >/dev/null 2>&1; cat <<B\na\nA\n$qjson\nB"),
            ("an unterminated body", "node_sh 0 <<EOS >/dev/null 2>&1\ntrue"),
            ("a command substitution in an unquoted body", "node_sh 0 <<EOS >/dev/null 2>&1\necho $(id)\nEOS"),
            ("a backtick in an unquoted body", "node_sh 0 <<EOS >/dev/null 2>&1\necho `id`\nEOS"),
            ("a command substitution after an escaped backslash", "node_sh 0 <<EOS >/dev/null 2>&1\necho \\\\$(id)\nEOS"),
            ("a command substitution in a <<- body", "node_sh 0 <<-EOS >/dev/null 2>&1\n\techo $(id)\n\tEOS"),
            ("a command substitution in a quoted-in-the-middle body", "node_sh 0 <<EOS >/dev/null 2>&1\necho \"$(id)\"\nEOS")):
        got = construct_findings(wrap(body))
        probe("#5655 construct negative control is flagged: %s" % label, len(got) > len(cb), str(got[len(cb):][:3]))
    for label, snip in (
            ("an escaped capture in an unquoted body", "node_sh 0 <<EOS >/dev/null 2>&1\necho \\$(id)\nEOS"),
            ("a capture in a quoted body", "node_sh 0 <<'EOS' >/dev/null 2>&1\necho $(id)\nEOS"),
            ("an arithmetic expansion in an unquoted body", "node_sh 0 <<EOS >/dev/null 2>&1\necho $((1 + 2))\nEOS"),
            ("sshd named in a body", "node_sh 0 <<'EOS' >/dev/null 2>&1\nsystemctl restart sshd\nEOS"),
            ("an ssh with SSH_BATCH after a <<- body", "node_sh 0 <<-EOS >/dev/null 2>&1\n\ttrue\n\tEOS\nssh %s h true" % B),
            ("an ssh with SSH_BATCH after a double-quoted delimiter body", 'node_sh 0 <<"EOS" >/dev/null 2>&1\ntrue\nEOS\nssh %s h true' % B),
            ("an ssh with SSH_BATCH after an empty delimiter body", "node_sh 0 <<'' >/dev/null 2>&1\ntrue\n\nssh %s h true" % B),
            ("a message naming <<", 'die "a << b"\nssh %s h true' % B),
            ("an arithmetic shift", "x=$(( (1 + 2) << 3 ))\nssh %s h true" % B),
            ("a here-document word in a comment", "true # <<E\nssh %s h true" % B),
            ("a terminator spelled like an operator", "node_sh 0 <<'<<X' >/dev/null 2>&1\ntrue\n<<X\nssh %s h true\nX" % B),
            ("a here-document word in single quotes", "printf '%%s' '<<E'\nssh %s h true\nE" % B)):
        txt = snip + "\n"
        bad = ssh_batch_findings(txt) + construct_findings(txt)
        seen = sum(1 for _, l, _ in logical_lines(txt) if re.search(r"(?<![\w$/.-])ssh\s+\$SSH_BATCH", l))
        probe("#5655 control is accepted: %s" % label, not bad and seen == snip.count("ssh " + B), str(bad))
    # <<< is no operator: the word after its first << is empty, since < ends a word, and the scan resumes after it
    # (mutants D1 and D1b of round 16). The here-string itself is a construct finding, so only the census is read.
    hs = "x=$(cat <<<EOS)\nssh %s h true\n<EOS\n" % B
    seen = sum(1 for _, l, _ in logical_lines(hs) if re.search(r"(?<![\w$/.-])ssh\s+\$SSH_BATCH", l))
    probe("#5655 the census reads an ssh after a here-string as code", not ssh_batch_findings(hs) and seen == 1,
          str(ssh_batch_findings(hs)))


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


def reply_len_padded_wc():
    """#4999: reply_len prints only digits and ' bytes' even where wc pads its count (BSD wc prints
    leading blanks); a GNU-only test cannot see that, so a PATH wc stand-in pads the real count."""
    fs = FED.read_text()
    defs = reply_defs(fs)
    real_wc = shutil.which("wc")
    with tempfile.TemporaryDirectory(dir=str(ROOT / ".local-runs")) as t:
        d = pathlib.Path(t)
        (d / "wc").write_text("#!/bin/bash\nn=\"$(%s \"$@\" | tr -cd 0123456789)\"\nprintf '%%8s\\t\\n' \"$n\"\n" % real_wc)
        (d / "wc").chmod(0o755)
        own = run_bash_bytes("printf abc | wc -c", d)
        probe("#4999 the padded wc stand-in pads the count", own.stdout == b"       3\t\n", repr(own.stdout))
        bad = []
        for b in (b"", b"abc", b"x" * 300, "é€".encode("utf-8"), b"a\nb\n"):
            r = run_bash_bytes("%s\nreply_len %s\n" % (defs, bq(b)), d)
            if r.stdout != b"%d bytes" % len(b):
                bad.append("%d:%r" % (len(b), r.stdout))
        probe("#4999 reply_len prints exactly the byte count and ' bytes' when wc pads its output", bool(defs) and not bad, " ".join(bad))


def ext_pin_5275():
    """#5275: AGE and pgvector pass only on their own labelled line after server_version, exactly once."""
    fs = FED.read_text()
    defs = reply_defs(fs)
    cases = (("the certified reply", "18.6\nage=1.8.0\nvector=0.8.6\n", True, True),
             ("a non-certified age line before a certified one", "18.6\nage=1.7.0\nage=1.8.0\nvector=0.8.6\n", False, True),
             ("age=1.8.0 on the server_version line", "age=1.8.0\nage=1.7.0\nvector=0.8.6\n", False, True),
             ("age=1.8.0 on the server_version line and no age row", "age=1.8.0\nvector=0.8.6\n", False, True),
             ("the age line twice", "18.6\nage=1.8.0\nage=1.8.0\nvector=0.8.6\n", False, True),
             ("no age row", "18.6\nvector=0.8.6\n", False, True),
             ("a non-certified vector line before a certified one", "18.6\nage=1.8.0\nvector=0.8.5\nvector=0.8.6\n", True, False),
             ("vector=0.8.6 on the server_version line", "vector=0.8.6\nage=1.8.0\nvector=0.8.5\n", True, False),
             ("vector=0.8.6 on the server_version line and no vector row", "vector=0.8.6\nage=1.8.0\n", True, False),
             ("the vector line twice", "18.6\nage=1.8.0\nvector=0.8.6\nvector=0.8.6\n", True, False),
             ("a trailing byte after the version", "18.6\nage=1.8.0 \nvector=0.8.6\r\n", False, False),
             # #5357: command substitution strips trailing newlines, so a repeated empty label must still count.
             ("the age label repeated empty and last", "18.6\nage=1.8.0\nage=\nvector=0.8.6\n", False, True),
             ("the vector label repeated empty and last", "18.6\nage=1.8.0\nvector=0.8.6\nvector=", True, False),
             ("both labels repeated empty and last", "18.6\nage=1.8.0\nage=\nvector=0.8.6\nvector=\n\n", False, False),
             # #5358: a label in the middle of a line is not a labelled line.
             ("a mid-line vector label", "18.6 (Ubuntu)\nage=1.8.0\n0.8.vector=6\n", True, False),
             ("a mid-line age label", "18.6 (Ubuntu)\n1.8.age=0\nvector=0.8.6\n", False, True),
             # #5415: label text in the middle of a line beside a valid labelled line must not fail a healthy node.
             ("a mid-line age label beside a valid age line", "18.6\nage=1.8.0\nx age=1.8.0\nvector=0.8.6\n", True, True),
             ("a mid-line vector label beside a valid vector line", "18.6\nage=1.8.0\nvector=0.8.6\nx vector=0.8.6\n", True, True),
             ("a mid-line age label beside a valid age line, other order", "18.6\nx age=1.7.0\nage=1.8.0\nvector=0.8.6\n", True, True))
    with tempfile.TemporaryDirectory(dir=str(ROOT / ".local-runs")) as t:
        d = pathlib.Path(t)
        for label, reply, want_age, want_vec in cases:
            r = run_versions(fs, defs, reply, d)
            out = r.stdout.splitlines()
            age = [l for l in out if " AGE " in l]
            vec = [l for l in out if " pgvector " in l]
            good = (bool(version_block(fs)) and len(age) == 1 and len(vec) == 1
                    and age[0].startswith("OK" if want_age else "NO") and vec[0].startswith("OK" if want_vec else "NO"))
            probe("#5275 %s gives AGE %s, pgvector %s" % (label, "PASS" if want_age else "FAIL", "PASS" if want_vec else "FAIL"),
                  good, "" if good else "%s %s" % (age, vec))


def comment_pin_5416():
    """#5416: the federate.sh closed-world comment names every silent word, declarator and stated limit the scan has."""
    fs = FED.read_text()
    start = fs.find("# Closed-world output (#4999")
    end = fs.find("# reply_status prints", start)
    block = fs[start:end] if start >= 0 and end > start else ""
    missing = [w for w in sorted(SILENT_CONSUMERS | DECLARATORS) if not re.search(r"(?<![\w-])" + re.escape(w) + r"(?![\w-])", block)]
    probe("#5416 the closed-world comment names every silent word and declarator the scan allows", bool(block) and not missing, str(missing))
    probe("#5418 the closed-world comment states that an undecidable form is reported", "#5418" in block
          and "a form it cannot decide is reported" in block and "is not resolved" not in block
          and "is not followed" not in block, "")
    probe("#5602 the closed-world comment states the proven-file rule for targets", "#5602" in block
          and "every literal path\n#    included, is the terminal" in block and "only a plain path" not in block
          and "starts with a literal character" not in block, "")
    probe("#5621 the closed-world comment states the by-name reader rule and its limits", "#5621" in block
          and "nor the working directory (cd,\n# pushd, popd, a subshell, env --chdir) decides" in block
          and "Stated limits:" in block and "bare name counts" not in block
          and "is taken as x, so" not in block and "relative name alone" not in block, "")
    probe("#5763 the closed-world comment states the root proof and the arithmetic limit", "#5763" in block
          and "are roots only while the scan proves their value" in block
          and "a variable in a target other than a root is followed" in block
          and "an integer that bash\n# arithmetic assigns" in block
          and "a variable in a target is followed" not in block, "")
    changelog = (ROOT / "changelog.d" / "4654.fixed.md").read_text()
    probe("#5416 the changelog does not call any member of the allowed set a known silent consumer",
          "known silent consumer" not in changelog and "#5418" in changelog, "")


def f2_id_lists_agree():
    fs = FED.read_text()
    # the #5602 fed_identity check also allows ":" (a federation identity is ai:<name>); it is not an id check
    lists = re.findall(r"\^(\[[^\]]*\])\{1,64\}\$", "\n".join(l for l in fs.splitlines() if "=~" in l and "1,64" in l
                                                             and '"$fid"' not in l))
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
    try:
        seg = (section(fed, "  # Neither the key nor any node reply may reach an xtrace log", "  for i in ")
               + section(fed, '  api_key="$(on_node', "  if [ -n \"$api_key\" ]; then"))
    except ValueError:
        seg = "  false"  # the suspension marker is gone: the behaviour probes below fail, not crash
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
    store_url_shape_locale_5764()
    store_url_premint_locale_5807()
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
    reply_len_padded_wc()
    pg_version_5172()
    ext_pin_5275()
    comment_pin_5416()
    node_streams_5171()
    ssh_batch_5274()
    heredoc_5655()
    file_roots_5763()
    verify_cost_5247()
    verify_trace_5237()
    f3_static_pins()
    print("RESULT: %s (%d failed)" % ("FAIL" if FAILS else "PASS", len(FAILS)))
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
