"""Guard for the tracked test-dashboard sources (#7313, review fixes F1/F2/F3/F7).

F1  every *state.json a dashboard page fetches must be a tracked file in public/, the live
    public/state.json that push-state.py writes, or the output of scripts/evidence/mcp-tools-state.py.
F2  one credential precedence (process env, then the first matching ~/.env line) for deploy.py and
    push-state.py; `export ` prefix and quotes accepted; account id validated before any URL is built.
F3  step 3 domain attach: only the Cloudflare "already exists" error is success.
F7  the wrangler subprocess has a timeout; a timeout exits non-zero.
Also: deploy.py --help exits 0 and never uses shell=True. No network: api() and subprocess are mocked.
"""
import ast
import contextlib
import importlib.util
import io
import json
import os
import re
import subprocess
import subprocess as sp
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

import cf_origin_7313 as origin_mod
from cf_origin_7313 import loaded_origins

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
FIXTURES = Path(__file__).resolve().parent / "fixtures"
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

    def _unreadable_log(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(self.cf.credential("CLOUDFLARE_API_TOKEN"), "")
        return err.getvalue()

    def test_unreadable_env_file_is_reported_not_swallowed(self):
        # CodeQL 482 py/empty-except: an unreadable home env file is logged with a fixed message
        # (exception type only), never silently passed; an absent file stays silent.
        # #7516: the log carries neither the path nor any credential value.
        (self.home / ".env").mkdir()
        log = self._unreadable_log()
        self.assertEqual(log, "warning: home env file is unreadable (IsADirectoryError)\n")
        self.assertNotIn(str(self.home), log)
        (self.home / ".env").rmdir()
        self.assertEqual(self._unreadable_log(), "")

    def test_unreadable_env_file_log_omits_path_and_secret_7516(self):
        env_file = self.home / ".env"
        env_file.write_text("CLOUDFLARE_API_TOKEN=" + SECRET_TOKEN + "\n")
        env_file.chmod(0)
        self.addCleanup(env_file.chmod, 0o600)
        if os.access(env_file, os.R_OK):
            self.skipTest("a privileged user reads a mode-0 file; the directory case covers the path")
        log = self._unreadable_log()
        self.assertEqual(log, "warning: home env file is unreadable (PermissionError)\n")
        self.assertNotIn(str(self.home), log)
        self.assertNotIn(".env", log)
        self.assertNotIn(SECRET_TOKEN, log)

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


def _expected_for(browser):
    """The helper-side expectation for one recorded browser result."""
    if browser == "PARSE-FAIL":
        return "unparsed"
    return None if browser == "none" else browser


class WhatwgOriginTable7313(unittest.TestCase):
    """#7512-#7515: the origin helper agrees with the recorded WHATWG `URL` result for every case.
    The 137 review r5 cases plus extra shapes; node is only needed to regenerate the fixture."""

    @classmethod
    def setUpClass(cls):
        cls.doc = json.loads((FIXTURES / "whatwg_origin_cases_7313.json").read_text(encoding="utf-8"))
        cls.page_origin = cls.doc["page_origin"]

    def test_fixture_has_the_137_review_cases(self):
        groups = [c["group"] for c in self.doc["cases"]]
        self.assertEqual(groups.count("review"), 137)
        self.assertGreaterEqual(groups.count("extra"), 80)

    def _check(self, group):
        cases = [c for c in self.doc["cases"] if c["group"] == group]
        self.assertTrue(cases)
        for case in cases:
            value, browser = case["input"], case["browser"]
            want = _expected_for(browser)
            with self.subTest(value=value, browser=browser):
                try:
                    got = origin_mod.parse_origin(value)
                except origin_mod.UnparsedURL:
                    got = "unparsed"
                if got == self.page_origin:
                    got = None  # the helper does not know the page's own origin; same origin loads nothing external
                self.assertEqual(got, want)
                found = loaded_origins('<img src="%s">' % value.replace("&", "&amp;").replace('"', "&quot;"))
                if want == "unparsed":
                    self.assertEqual(len(found), 1, found)
                    self.assertTrue(next(iter(found)).startswith("unparsed:"), found)
                else:
                    self.assertEqual(found - {self.page_origin}, set() if want is None else {want})

    def test_all_137_review_cases_match_the_browser(self):
        self._check("review")

    def test_extra_cases_match_the_browser(self):
        self._check("extra")


class FailClosedUrlForms7313(unittest.TestCase):
    """One assertion per form named by review r5 (#7512-#7515)."""

    def _one(self, value):
        return loaded_origins('<img src="%s">' % value)

    def test_7512_ipv6_percent_encoded_slashless_underscore_idn(self):
        self.assertEqual(self._one("https://[::1]:8443/x"), {"https://[::1]:8443"})
        self.assertEqual(self._one("https://[::1]/x"), {"https://[::1]"})
        self.assertEqual(self._one("http://[2001:db8::1]:80/x"), {"http://[2001:db8::1]"})
        self.assertEqual(self._one("//[::1]:9000/x"), {"https://[::1]:9000"})
        self.assertEqual(self._one("https://%65xample.com/x"), {"https://example.com"})
        self.assertEqual(self._one("http:noslash.example/x"), {"http://noslash.example"})
        self.assertEqual(self._one("https://a_b.example/x"), {"https://a_b.example"})
        self.assertEqual(self._one("https://ex\u00e4mple.com/x"), {"https://xn--exmple-cua.com"})

    def test_7512_unparseable_authority_is_a_guard_failure_not_a_silent_drop(self):
        for value in ("https://[::1/x", "https://exa%mple/x", "https://:80/x", "//x.example:abc/x"):
            found = self._one(value)
            self.assertEqual(found, {"unparsed:" + value}, value)

    def test_7513_port_zero_is_a_real_port(self):
        self.assertEqual(self._one("https://p.example:0/x"), {"https://p.example:0"})
        self.assertEqual(self._one("https://p.example:00443/x"), {"https://p.example"})

    def test_7514_userinfo_ends_at_the_last_at_sign(self):
        self.assertEqual(self._one("https://u:p" + AT + "ss" + AT + "ui3.example/x"), {"https://ui3.example"})
        self.assertEqual(self._one("https://a" + AT + "b" + AT + "ui4.example:8443/x"), {"https://ui4.example:8443"})

    def test_7515_out_of_range_port_and_numeric_hosts(self):
        for value in ("https://p.example:65536/x", "https://p.example:99999/x"):
            self.assertEqual(self._one(value), {"unparsed:" + value}, value)
        self.assertEqual(self._one("https://0x7f.1/x"), {"https://127.0.0.1"})
        self.assertEqual(self._one("https://0177.0.0.1:8443/x"), {"https://127.0.0.1:8443"})


class CspSourceList7313(unittest.TestCase):
    """#7515: CSP host-sources are parsed case-insensitively on the scheme, http sources are read, and a
    `:*` port is an explicit wildcard that the subset check honours."""

    def test_scheme_and_host_are_case_insensitive(self):
        sources = origin_mod.csp_sources("style-src 'self' HTTPS://Fonts.GoogleAPIs.com; font-src Http://f.example:8080")
        self.assertEqual([(s.scheme, s.host, s.port) for s in sources],
                         [("https", "fonts.googleapis.com", ""), ("http", "f.example", "8080")])

    def test_default_port_is_normalised(self):
        (src,) = origin_mod.csp_sources("img-src https://a.example:443")
        self.assertEqual(src.port, "")

    def test_port_wildcard_matches_any_port_but_a_plain_source_only_the_default(self):
        (wild,) = origin_mod.csp_sources("img-src https://a.example:*")
        (plain,) = origin_mod.csp_sources("img-src https://a.example")
        self.assertEqual(wild.port, "*")
        for origin in ("https://a.example", "https://a.example:8443"):
            self.assertTrue(origin_mod.source_allows(wild, origin), origin)
        self.assertTrue(origin_mod.source_allows(plain, "https://a.example"))
        self.assertFalse(origin_mod.source_allows(plain, "https://a.example:8443"))
        self.assertFalse(origin_mod.source_allows(plain, "http://a.example"))

    def test_keywords_directive_names_and_scheme_sources_are_not_hosts(self):
        sources = origin_mod.csp_sources("default-src 'self'; img-src 'self' data:; script-src 'unsafe-inline'")
        self.assertEqual([s for s in sources if s.host], [])

    def test_unrecognised_source_expression_fails_closed(self):
        with self.assertRaises(ValueError):
            origin_mod.csp_sources("img-src https://a.example:abc")


class PublicSnapshotHygiene7518(unittest.TestCase):
    """#7518: nothing under public/ (deployed to the public dashboard) names an internal node or path,
    and the generators that write state files scrub them and refuse to write what is left."""

    def test_no_public_json_names_an_internal_host_or_path(self):
        hostscrub = _load("hostscrub_7518_t", "hostscrub.py")
        for path in sorted(PUBLIC.glob("*.json")):
            self.assertEqual(hostscrub.find_leaks(path.read_text(encoding="utf-8")), [], path.name)

    def test_scrub_replaces_hostnames_and_paths_in_nested_values(self):
        hostscrub = _load("hostscrub_7518_s", "hostscrub.py")
        node = hostscrub.INTERNAL_HOSTNAMES[0]
        record = {"note": '{"agent_id": "host:%s", "from": "ai:x@%s"}' % (node, node.upper()),
                  "run_dir": "/home/someone/run-1", "deep": [{"p": "/mnt/disk1/x"}, "/ai-" + "scratch/y", 3, None]}
        clean = hostscrub.scrub(record)
        text = json.dumps(clean)
        self.assertEqual(hostscrub.find_leaks(text), [])
        self.assertNotIn(node, text.lower())
        self.assertIn("host:" + hostscrub.REDACTED, clean["note"])
        self.assertEqual(clean["deep"][2:], [3, None])

    def test_mcp_tools_state_generator_scrubs_before_writing(self):
        hostscrub = _load("hostscrub_7518_g", "hostscrub.py")
        node = hostscrub.INTERNAL_HOSTNAMES[0]
        SCRATCH.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=str(SCRATCH)) as tmp:
            run_dir = Path(tmp) / ("run-" + node)
            run_dir.mkdir()
            (run_dir / "tools-list.json").write_text(json.dumps([{"name": "memory_a"}, {"name": "memory_b"}]))
            out = Path(tmp) / "out" / "mcp-tools-state.json"
            spec = importlib.util.spec_from_file_location("mcp_tools_state_7518", MCP_PRODUCER)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            with mock.patch.object(mod, "git", return_value="0" * 40), \
                    mock.patch.object(sys, "argv", ["mcp-tools-state.py", "--run-dir", str(run_dir), "--out", str(out)]), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(mod.main(), 0)
            text = out.read_text(encoding="utf-8")
            self.assertEqual(hostscrub.find_leaks(text), [])
            self.assertNotIn(node, text.lower())
            self.assertEqual(json.loads(text)["total"], 2)

    def test_push_state_scrubs_the_live_state_before_writing(self):
        hostscrub = _load("hostscrub_7518_p", "hostscrub.py")
        node = hostscrub.INTERNAL_HOSTNAMES[0]
        mod = _load("push_state_7518", "push-state.py")
        SCRATCH.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=str(SCRATCH)) as tmp:
            src = Path(tmp) / "in.json"
            src.write_text(json.dumps({"agents": [{"node": node}]}))
            (Path(tmp) / "public").mkdir()
            with mock.patch.object(mod, "HERE", Path(tmp)), \
                    mock.patch.object(mod.cfcommon, "load_credentials", side_effect=mod.cfcommon.CredentialError("none")), \
                    mock.patch.object(sys, "argv", ["push-state.py", str(src)]), \
                    contextlib.redirect_stderr(io.StringIO()):
                mod.main()
            written = (Path(tmp) / "public" / "state.json").read_text(encoding="utf-8")
            self.assertNotIn(node, written.lower())


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

    def test_index_ring_rejects_a_non_list_dimensions_field_7517(self):
        # removing the dead `dims.filter(...)` line also removed the implicit TypeError for a non-list
        # `dimensions`; the ring must keep its placeholder (the explicit throw skips the ring code and
        # leaves the poll's catch to mark the page offline), not paint a real-looking 0%.
        text = (PUBLIC / "index.html").read_text()
        render = text[text.index("function renderAll(D){"):text.index("/* ---------- live poll ---------- */")]
        guard = re.search(r"if\(!Array\.isArray\(dims\)\)\s*throw new TypeError\(", render)
        self.assertIsNotNone(guard, "renderAll lost its Array.isArray(dims) guard")
        self.assertLess(guard.start(), render.index('getElementById("ringpct")'))
        self.assertLess(render.index("_S(()=>board(dims))"), guard.start(), "panels must render before the guard")

    def test_headers_csp_matches_loaded_origins(self):
        headers = (PUBLIC / "_headers").read_text()
        csp = re.search(r"Content-Security-Policy: (.*)", headers)
        self.assertIsNotNone(csp, "no Content-Security-Policy")
        csp = csp.group(1)
        self.assertIn("frame-ancestors 'none'", csp)
        self.assertIn("X-Frame-Options: DENY", headers)
        self.assertEqual(headers.count("/state.json"), 0, "redundant /state.json rule (covered by /*.json)")
        sources = origin_mod.csp_sources(csp)
        loaded = set()
        for page in sorted(PUBLIC.glob("*.html")):
            loaded.update(loaded_origins(page.read_text()))
        self.assertTrue(loaded, "expected external stylesheet origins")
        blocked = {o for o in loaded if not any(origin_mod.source_allows(s, o) for s in sources)}
        self.assertEqual(blocked, set(), "origins loaded but not allowed by CSP (or unparsed): %s" % blocked)
        unused = [s for s in sources if s.host and s.host != "fonts.gstatic.com"
                  and not any(origin_mod.source_allows(s, o) for o in loaded)]
        self.assertEqual(unused, [], "CSP allows unused origins")


class DeployCli7313(unittest.TestCase):
    def test_deploy_help_and_no_shell_true(self):
        p = subprocess.run([sys.executable, str(DASH / "deploy.py"), "--help"],
                           capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        for name in ("deploy.py", "push-state.py", "cfcommon.py"):
            self.assertNotIn(NO_SHELL, (DASH / name).read_text())


SELF_FILE = Path(__file__).resolve()
HOME_ENV_LITERAL = re.compile("~/" + r"\." + "env")  # built from parts so this file does not hold the literal itself
SENSITIVE_NAME = re.compile(r"secret|passw|token|credential", re.IGNORECASE)
FILE_WRITERS = frozenset(("write_text", "write_bytes", "write"))


def _pr_python_sources():
    """Every Python file this PR adds, as (path, text)."""
    paths = sorted(DASH.glob("*.py")) + [SELF_FILE, SELF_FILE.parent / "cf_origin_7313.py", MCP_PRODUCER]
    paths += sorted(FIXTURES.glob("*.py"))
    return [(p, p.read_text(encoding="utf-8")) for p in paths]


class SourceHygiene7313(unittest.TestCase):
    """#7549 (CodeQL py/import-and-import-from), #7553 (CodeQL clear-text storage), #7556 (no literal home env
    path, no token-line layout in a docstring)."""

    def test_7549_no_module_is_imported_with_import_and_import_from(self):
        for path, text in _pr_python_sources():
            tree = ast.parse(text)
            plain = {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
            named = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
            self.assertEqual(plain & named, set(), "%s imports a module both ways" % path.name)

    def test_7553_no_secret_named_value_is_written_to_a_file(self):
        for path, text in _pr_python_sources():
            for call in (n for n in ast.walk(ast.parse(text)) if isinstance(n, ast.Call)):
                func = call.func
                if not (isinstance(func, ast.Attribute) and func.attr in FILE_WRITERS):
                    continue
                names = [s.id for arg in call.args for s in ast.walk(arg) if isinstance(s, ast.Name)]
                bad = [n for n in names if SENSITIVE_NAME.search(n)]
                self.assertEqual(bad, [], "%s:%d writes %s to a file" % (path.name, call.lineno, bad))

    def test_7553_the_fake_probe_file_is_owner_only(self):
        text = SELF_FILE.read_text(encoding="utf-8")
        self.assertRegex(text, r"os\.open\([^)]*0o600", "the unreadable-env probe must create its file owner-only")

    def test_7556_no_literal_home_env_path_in_code_or_docstrings(self):
        for path, text in _pr_python_sources():
            self.assertIsNone(HOME_ENV_LITERAL.search(text), "%s names the home env file literally" % path.name)

    def test_7556_docstrings_do_not_describe_the_token_lines_of_the_env_file(self):
        for name in ("push-state.py", "deploy.py", "cfcommon.py"):
            text = (DASH / name).read_text(encoding="utf-8")
            self.assertIsNone(re.search(r"(?i)\b(two|second|2)\b[^.\n]{0,40}\btoken", text), name)
            self.assertNotIn("Workers AI", text, name)


if __name__ == "__main__":
    unittest.main()
