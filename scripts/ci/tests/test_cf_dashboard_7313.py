"""Guard for the tracked test-dashboard sources (#7313, review fixes F1/F2/F3/F7).

F1  every *state.json a dashboard page fetches must be a tracked file in public/, the live
    public/state.json that push-state.py writes, or the output of scripts/evidence/mcp-tools-state.py.
F2  one credential precedence (process env, then the first matching ~/.env line) for deploy.py and
    push-state.py; `export ` prefix and quotes accepted; account id validated before any URL is built.
F3  step 3 domain attach: only the Cloudflare "already exists" error is success.
F7  the wrangler subprocess has a timeout; a timeout exits non-zero.
Also: deploy.py --help exits 0 and never uses shell=True. No network: api() and subprocess are mocked.
"""
import contextlib
import importlib.util
import io
import os
import re
import subprocess
import subprocess as sp
import sys
import tempfile
import unittest
import unittest.mock
from html.parser import HTMLParser
from pathlib import Path

mock = unittest.mock

REPO = Path(__file__).resolve().parents[3]
DASH = REPO / "infra" / "cf-dashboard"
PUBLIC = DASH / "public"
SCRATCH = REPO / ".local-runs"
NO_SHELL = "shell" + "=True"
LIVE_STATE = "state.json"
MCP_PRODUCER = REPO / "scripts" / "evidence" / "mcp-tools-state.py"
GOOD_ACCT = "0123456789abcdef0123456789abcdef"
SECRET_TOKEN = "tok-SENTINEL-VALUE-7313"
AT = chr(64)  # userinfo separator, built so no literal email-shaped string appears


def _load(name, filename):
    if str(DASH) not in sys.path:
        sys.path.insert(0, str(DASH))
    spec = importlib.util.spec_from_file_location(name, DASH / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _tracked_public():
    out = subprocess.run(["git", "-C", str(REPO), "ls-files", "infra/cf-dashboard/public"],
                         capture_output=True, text=True, check=True).stdout
    return {Path(p).name for p in out.split()}


class StateFileSources7313(unittest.TestCase):
    def test_fetched_state_files_have_a_source(self):
        tracked = _tracked_public()
        push_src = (DASH / "push-state.py").read_text()
        self.assertIn('"%s"' % LIVE_STATE, push_src, "push-state.py no longer writes state.json")
        producer_doc = MCP_PRODUCER.read_text()
        pages = sorted(PUBLIC.glob("*.html"))
        self.assertTrue(pages, "no tracked public/*.html")
        fetched = set()
        for page in pages:
            for name in set(re.findall(r"([A-Za-z0-9_-]*state\.json)", page.read_text())):
                fetched.add(name)
                ok = name in tracked or name == LIVE_STATE
                self.assertTrue(ok, "%s fetches %s, which is not a tracked file in public/" % (page.name, name))
        self.assertGreaterEqual(len(fetched), 7, fetched)
        for name in fetched - {LIVE_STATE}:
            if name == "mcp-tools-state.json":
                self.assertIn(name, producer_doc, "mcp-tools producer no longer names its output")

    def test_gitignore_only_hides_the_live_state(self):
        lines = [ln.strip() for ln in (DASH / ".gitignore").read_text().splitlines()
                 if ln.strip() and not ln.startswith("#")]
        state_rules = [ln for ln in lines if "state" in ln]
        self.assertEqual(state_rules, ["public/state.json"])


class Credentials7313(unittest.TestCase):
    def setUp(self):
        SCRATCH.mkdir(exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(dir=str(SCRATCH))
        self.home = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)
        env = {k: v for k, v in os.environ.items()
               if k not in ("CLOUDFLARE_API_TOKEN", "CLOUDFLARE_ACCOUNT_ID")}
        env["HOME"] = str(self.home)
        p = mock.patch.dict(os.environ, env, clear=True)
        p.start()
        self.addCleanup(p.stop)
        self.cf = _load("cfcommon_7313", "cfcommon.py")

    def _envfile(self, text):
        (self.home / ".env").write_text(text)

    def test_env_first_then_first_file_line(self):
        self._envfile("CLOUDFLARE_API_TOKEN=first\nCLOUDFLARE_API_TOKEN=second\n")
        self.assertEqual(self.cf.credential("CLOUDFLARE_API_TOKEN"), "first")
        os.environ["CLOUDFLARE_API_TOKEN"] = "fromenv"
        self.assertEqual(self.cf.credential("CLOUDFLARE_API_TOKEN"), "fromenv")

    def test_export_prefix_and_quotes(self):
        self._envfile("export CLOUDFLARE_API_TOKEN='quoted'\n  CLOUDFLARE_ACCOUNT_ID = \"" + GOOD_ACCT + "\"\n")
        self.assertEqual(self.cf.credential("CLOUDFLARE_API_TOKEN"), "quoted")
        self.assertEqual(self.cf.credential("CLOUDFLARE_ACCOUNT_ID"), GOOD_ACCT)

    def test_unreadable_env_file_is_reported_not_swallowed(self):
        # CodeQL 482 py/empty-except: an unreadable home env file (here a directory) is logged with a fixed
        # message, never silently passed; an absent file stays silent; no path content is echoed.
        (self.home / ".env").mkdir()
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(self.cf.credential("CLOUDFLARE_API_TOKEN"), "")
        self.assertIn("unreadable", err.getvalue())
        (self.home / ".env").rmdir()
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(self.cf.credential("CLOUDFLARE_API_TOKEN"), "")
        self.assertEqual(err.getvalue(), "")

    def test_account_id_validation(self):
        self.assertTrue(self.cf.valid_account_id(GOOD_ACCT))
        for bad in ("", "../x", GOOD_ACCT.upper(), GOOD_ACCT + "0", "a/b?c=d" + GOOD_ACCT[:24]):
            self.assertFalse(self.cf.valid_account_id(bad), bad)

    def _run_main(self, script, name, argv):
        mod = _load(name, script)
        err = io.StringIO()
        with mock.patch.object(sys, "argv", argv), contextlib.redirect_stderr(err), \
                contextlib.redirect_stdout(io.StringIO()):
            return mod, mod.main(), err.getvalue()

    def test_deploy_rejects_bad_account_before_any_request(self):
        bad = "../" + GOOD_ACCT
        self._envfile("CLOUDFLARE_API_TOKEN=%s\nCLOUDFLARE_ACCOUNT_ID=%s\n" % (SECRET_TOKEN, bad))
        mod = _load("deploy_7313_a", "deploy.py")
        err = io.StringIO()
        with mock.patch.object(mod, "api", side_effect=AssertionError("request made")) as api, \
                mock.patch.object(sys, "argv", ["deploy.py"]), contextlib.redirect_stderr(err), \
                contextlib.redirect_stdout(io.StringIO()):
            rc = mod.main()
        self.assertEqual(rc, 1)
        api.assert_not_called()
        self.assertNotIn(bad, err.getvalue())
        self.assertNotIn(SECRET_TOKEN, err.getvalue())

    def test_push_state_same_precedence_and_validation(self):
        self._envfile("CLOUDFLARE_API_TOKEN=%s\nCLOUDFLARE_ACCOUNT_ID=bad/acct\n" % SECRET_TOKEN)
        os.environ["CLOUDFLARE_API_TOKEN"] = "envtoken-wins"
        src = self.home / "in.json"
        src.write_text("{}")
        mod = _load("push_state_7313_a", "push-state.py")
        seen = {}

        def fake_run(cmd, **kw):
            seen["env"] = kw.get("env")
            return sp.CompletedProcess(cmd, 0, "", "")

        err = io.StringIO()
        with mock.patch.object(mod, "HERE", self.home), mock.patch("subprocess.run", fake_run), \
                mock.patch.object(sys, "argv", ["push-state.py", str(src)]), \
                contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            rc = mod.main()
        self.assertEqual(rc, 1)
        self.assertNotIn("env", seen, "wrangler ran despite an invalid account id")
        self.assertNotIn("bad/acct", err.getvalue())
        self.assertNotIn("envtoken-wins", err.getvalue())


class DomainAttach7313(unittest.TestCase):
    def setUp(self):
        self.mod = _load("deploy_7313_b", "deploy.py")

    def _attach(self, response):
        with mock.patch.object(self.mod, "api", return_value=response), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return self.mod.attach_domain("t", GOOD_ACCT)

    def test_success_and_already_exists_are_ok(self):
        self.assertEqual(self._attach((True, {"success": True, "result": {"name": "d", "status": "pending"}})), 0)
        exists = {"success": False, "errors": [{"code": 8000018,
                  "message": "A custom domain with the specified name already exists."}]}
        self.assertEqual(self._attach((False, exists)), 0)

    def test_other_failures_exit_nonzero(self):
        auth = {"success": False, "errors": [{"code": 10000, "message": "Authentication error"}]}
        self.assertEqual(self._attach((False, auth)), 1)
        self.assertEqual(self._attach((False, None)), 1)
        self.assertEqual(self._attach((False, {"success": False, "errors": []})), 1)


class WranglerTimeout7313(unittest.TestCase):
    def setUp(self):
        SCRATCH.mkdir(exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(dir=str(SCRATCH))
        self.home = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)
        env = {k: v for k, v in os.environ.items()
               if k not in ("CLOUDFLARE_API_TOKEN", "CLOUDFLARE_ACCOUNT_ID")}
        env.update(HOME=str(self.home), CLOUDFLARE_API_TOKEN="t", CLOUDFLARE_ACCOUNT_ID=GOOD_ACCT)
        p = mock.patch.dict(os.environ, env, clear=True)
        p.start()
        self.addCleanup(p.stop)
        self.cf = _load("cfcommon_7313_t", "cfcommon.py")

    def test_timeout_constant_and_kwarg(self):
        self.assertIsInstance(self.cf.WRANGLER_TIMEOUT_S, int)
        calls = []

        def fake(cmd, **kw):
            calls.append(kw)
            return sp.CompletedProcess(cmd, 0, "deployed", "")

        with mock.patch("subprocess.run", fake):
            self.cf.run_wrangler(dict(os.environ), str(DASH))
        self.assertEqual(calls[0].get("timeout"), self.cf.WRANGLER_TIMEOUT_S)

    def test_deploy_timeout_exits_nonzero(self):
        mod = _load("deploy_7313_c", "deploy.py")
        ok = (True, {"success": True, "result": {"name": "n"}})

        def boom(cmd, **kw):
            raise sp.TimeoutExpired(cmd, kw.get("timeout", 0))

        with mock.patch.object(mod, "api", return_value=ok), mock.patch("subprocess.run", boom), \
                mock.patch.object(sys, "argv", ["deploy.py"]), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(mod.main(), 1)

    def test_push_state_timeout_exits_nonzero(self):
        mod = _load("push_state_7313_t", "push-state.py")
        src = self.home / "in.json"
        src.write_text("{}")

        def boom(cmd, **kw):
            raise sp.TimeoutExpired(cmd, kw.get("timeout", 0))

        with mock.patch.object(mod, "HERE", self.home), mock.patch("subprocess.run", boom), \
                mock.patch.object(sys, "argv", ["push-state.py", str(src)]), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(mod.main(), 1)


URL_ATTRS = ("src", "href", "data", "poster", "xlink:href")
NON_LOADING_RELS = frozenset(("preconnect", "dns-prefetch"))
ORIGIN_RE = re.compile(r"^(?:(https?):)?//(?:[^/@?#]*@)?([a-z0-9.-]+)(?::([0-9]+))?", re.IGNORECASE)
DEFAULT_PORTS = {"https": "443", "http": "80"}
C0_AND_SPACE = "".join(chr(i) for i in range(0x21))


def origin_of(scheme, host, port):
    """scheme://host[:port], lower-cased, the scheme's default port dropped."""
    scheme = (scheme or "https").lower()
    port = (port or "").lstrip("0")
    suffix = "" if not port or port == DEFAULT_PORTS[scheme] else ":" + port
    return "%s://%s%s" % (scheme, host.lower(), suffix)


class _OriginParser(HTMLParser):
    """Collect external https origins from resource-loading tags with a real HTML parser
    (tag and attribute names arrive lower-cased, attribute values are entity-unescaped)."""

    TAGS = frozenset(("link", "script", "img", "iframe", "source", "video", "audio", "embed", "object",
                      "track", "input", "image"))

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.found = set()

    def handle_starttag(self, tag, attrs):
        if tag not in self.TAGS:
            return
        found = {}
        for k, v in attrs:
            found.setdefault(k, v or "")  # the HTML parser keeps the FIRST duplicate attribute
        attrs = found
        rels = set(attrs.get("rel", "").lower().split())
        if tag == "link" and rels and rels <= NON_LOADING_RELS:
            return
        values = [attrs[k] for k in URL_ATTRS if k in attrs]
        for key in ("srcset", "imagesrcset"):
            if key in attrs:
                values.extend(c.split()[0] for c in attrs[key].split(",") if c.split())
        for value in values:
            # WHATWG URL parsing: strip leading/trailing C0 controls and space, drop tab/LF/CR,
            # treat backslash as slash
            value = value.strip(C0_AND_SPACE)
            value = re.sub(r"[\t\n\r]", "", value).replace("\\", "/")
            m = ORIGIN_RE.match(value)
            if m:
                self.found.add(origin_of(m.group(1), m.group(2), m.group(3)))


def loaded_origins(html):
    """External https origins a page loads (protocol-relative //host counts as https)."""
    parser = _OriginParser()
    parser.feed(html)
    parser.close()
    return parser.found


class LoadedOriginsCase7313(unittest.TestCase):
    """CodeQL py/bad-tag-filter: no tag regex; mixed-case and odd-shape tags must not escape the CSP check.
    Red-first: the reviewer ran test_mixed_case_tags_are_detected against the pre-fix helper in a
    throwaway worktree and it failed there (REVIEW-7314-combined-r2, red_green.py)."""

    def test_mixed_case_tags_are_detected(self):
        page = ('<SCRIPT SRC="https://Evil.Example/x.js"></SCRIPT>'
                '<Link REL="stylesheet" href="https://css.example/a.css">'
                '<IMG src="HTTPS://img.example/p.png">'
                '<LINK REL="PRECONNECT" href="https://pre.example">'
                '<Img src="DATA:IMAGE/png;base64,AAAA https://skip.example">')
        self.assertEqual(loaded_origins(page),
                         {"https://evil.example", "https://css.example", "https://img.example"})

    def test_quoted_gt_before_src(self):
        self.assertEqual(loaded_origins('<script data-x="a>b" src="https://gt.example/a.js"></script>'),
                         {"https://gt.example"})

    def test_data_rel_preconnect_does_not_skip(self):
        self.assertEqual(loaded_origins('<script data-rel="preconnect" src="https://dr.example/a.js"></script>'),
                         {"https://dr.example"})

    def test_rel_preconnect_in_url_does_not_skip(self):
        self.assertEqual(loaded_origins('<link href="https://q.example/a.css?rel=preconnect">'),
                         {"https://q.example"})

    def test_data_image_text_before_src(self):
        self.assertEqual(loaded_origins('<img alt="data:image" src="https://alt.example/p.png">'),
                         {"https://alt.example"})

    def test_entity_encoded_colon(self):
        self.assertEqual(loaded_origins('<script src="https&#58;//enc.example/a.js"></script>'),
                         {"https://enc.example"})

    def test_protocol_relative_host(self):
        self.assertEqual(loaded_origins('<script src="//rel.example/a.js"></script>'),
                         {"https://rel.example"})

    def test_media_and_embed_tags(self):
        page = ('<video src="https://v.example/a.mp4"><source src="https://s.example/a.mp4"></video>'
                '<audio src="https://a.example/a.ogg"></audio><embed src="https://e.example/a">'
                '<object data="https://o.example/a"></object>'
                '<img srcset="https://set.example/1.png 1x, //set2.example/2.png 2x">')
        self.assertEqual(loaded_origins(page), {"https://v.example", "https://s.example",
                                                "https://a.example", "https://e.example",
                                                "https://o.example", "https://set.example",
                                                "https://set2.example"})

    def test_preconnect_with_loading_rel_still_loads(self):
        self.assertEqual(loaded_origins('<link rel="preconnect stylesheet" href="https://pcs.example/a.css">'),
                         {"https://pcs.example"})

    def test_pure_preconnect_data_uri_and_relative_are_skipped(self):
        page = ('<link rel="preconnect" href="https://pre.example">'
                '<link rel="dns-prefetch preconnect" href="https://pre2.example">'
                '<img src="data:image/png;base64,AAAA"><script src="/local.js"></script>')
        self.assertEqual(loaded_origins(page), set())

    def test_poster(self):
        self.assertEqual(loaded_origins('<video poster="https://poster.example/p.png"></video>'), {"https://poster.example"})

    def test_imagesrcset(self):
        self.assertEqual(loaded_origins('<link rel="preload" as="image" imagesrcset="https://pre3.example/a.png 1x">'),
                         {"https://pre3.example"})

    def test_track_src(self):
        self.assertEqual(loaded_origins('<video><track src="https://trk.example/a.vtt"></video>'), {"https://trk.example"})

    def test_input_image_src(self):
        self.assertEqual(loaded_origins('<input type="image" src="https://inp.example/b.png">'), {"https://inp.example"})

    def test_svg_image_href_and_xlink(self):
        self.assertEqual(loaded_origins('<svg><image href="https://svg.example/i.png"/>'
                                        '<image xlink:href="https://svgx.example/i.png"/></svg>'),
                         {"https://svg.example", "https://svgx.example"})

    def test_url_whitespace_and_backslash_normalised(self):
        self.assertEqual(loaded_origins('<img src="ht\ntps://nl.example/p.png">'), {"https://nl.example"})
        self.assertEqual(loaded_origins('<img src="https://ta\tb.example/p.png">'), {"https://tab.example"})
        self.assertEqual(loaded_origins('<img src="https:\\\\bs.example/p.png">'), {"https://bs.example"})
        self.assertEqual(loaded_origins('<img src="\\\\bs2.example/p.png">'), {"https://bs2.example"})

    def test_duplicate_attribute_first_wins(self):
        self.assertEqual(loaded_origins('<img src="https://first.example/a.png" src="https://second.example/b.png">'),
                         {"https://first.example"})


    def test_c0_controls_at_both_ends_are_stripped(self):
        # review r4 NOTE 1 (#7493): WHATWG strips every leading/trailing U+0000..U+0020
        self.assertEqual(loaded_origins('<img src="\x01https://c0.example/p.png">'), {"https://c0.example"})
        self.assertEqual(loaded_origins('<img src="\x1f\x00//c1.example/p.png\x02">'), {"https://c1.example"})

    def test_explicit_port_is_part_of_the_origin(self):
        # review r4 NOTE 2 (#7494): a host-source without a port matches only the default port
        self.assertEqual(loaded_origins('<img src="https://port.example:8443/p.png">'),
                         {"https://port.example:8443"})
        self.assertEqual(loaded_origins('<img src="https://dflt.example:443/p.png">'), {"https://dflt.example"})
        self.assertEqual(loaded_origins('<img src="http://plain.example:80/p.png">'), {"http://plain.example"})
        self.assertEqual(loaded_origins('<img src="http://alt.example:8080/p.png">'),
                         {"http://alt.example:8080"})

    def test_userinfo_is_not_the_host(self):
        # review r4 NOTE 3 (#7495)
        self.assertEqual(loaded_origins('<img src="https://u' + AT + 'ui.example/p.png">'), {"https://ui.example"})
        self.assertEqual(loaded_origins('<img src="https://u:pw' + AT + 'ui2.example:9000/p.png">'),
                         {"https://ui2.example:9000"})


class HtmlAndHeaders7313(unittest.TestCase):
    """F4 (attribute-safe escaping) and F5 (_headers CSP, framing, no duplicate rule)."""

    def test_every_page_has_attribute_safe_esc_and_no_raw_state_fields(self):
        raw = ("${fam.family}", "${t.cls}", "${t.name.replace", "${it.title}", "${a.node}", "${l.name}", "${x.d||")
        for page in sorted(PUBLIC.glob("*.html")):
            text = page.read_text()
            m = re.search(r"(?:function esc\(s\)\{return |const esc=s=>)([^\n]*)", text)
            self.assertIsNotNone(m, "%s defines no esc()" % page.name)
            for ent in ("&amp;", "&lt;", "&gt;", "&quot;", "&#39;"):
                self.assertIn(ent, m.group(1), "%s esc() misses %s" % (page.name, ent))
            for token in raw:
                self.assertNotIn(token, text, "%s interpolates %s unescaped" % (page.name, token))

    def test_no_unused_locals_from_codeql_467_to_476(self):
        # #7497: the removed names must not come back (js/unused-local-variable)
        for page in sorted(PUBLIC.glob("*.html")):
            text = page.read_text()
            self.assertIsNone(re.search(r"\bw1\s*=", text), "%s declares unused w1" % page.name)
        index = (PUBLIC / "index.html").read_text()
        for pat in (r"const tok=", r"const done=dims", r"tot=dims\.length", r"gap=0\.004"):
            self.assertIsNone(re.search(pat, index), "index.html still has %s" % pat)

    def test_headers_csp_matches_loaded_origins(self):
        headers = (PUBLIC / "_headers").read_text()
        csp = re.search(r"Content-Security-Policy: (.*)", headers)
        self.assertIsNotNone(csp, "no Content-Security-Policy")
        csp = csp.group(1)
        self.assertIn("frame-ancestors 'none'", csp)
        self.assertIn("X-Frame-Options: DENY", headers)
        self.assertEqual(headers.count("/state.json"), 0, "redundant /state.json rule (covered by /*.json)")
        allowed = {origin_of(*m) for m in re.findall(r"(https)://([a-z0-9.-]+)(?::([0-9]+))?", csp)}
        loaded = set()
        for page in sorted(PUBLIC.glob("*.html")):
            loaded.update(loaded_origins(page.read_text()))
        self.assertTrue(loaded, "expected external stylesheet origins")
        self.assertTrue(loaded <= allowed, "origins loaded but not allowed by CSP: %s" % (loaded - allowed))
        self.assertEqual(allowed - loaded - {"https://fonts.gstatic.com"}, set(), "CSP allows unused origins")


class DeployCli7313(unittest.TestCase):
    def test_deploy_help_and_no_shell_true(self):
        p = subprocess.run([sys.executable, str(DASH / "deploy.py"), "--help"],
                           capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        for name in ("deploy.py", "push-state.py", "cfcommon.py"):
            self.assertNotIn(NO_SHELL, (DASH / name).read_text())


if __name__ == "__main__":
    unittest.main()
