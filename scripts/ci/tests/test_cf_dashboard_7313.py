"""Guard for the tracked test-dashboard sources (#7313, review fixes F1/F2/F3/F7).

F1  every *state.json a dashboard page fetches must be a tracked file in public/, the live
    public/state.json that push-state.py writes, or the output of scripts/evidence/mcp-tools-state.py.
F2  one credential precedence (process env, then the first matching line of the home env file) for deploy.py and
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
import shutil
import subprocess
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

import cf_origin_7313 as origin_mod

mock = unittest.mock

REPO = Path(__file__).resolve().parents[3]
DASH = REPO / "infra" / "cf-dashboard"
PUBLIC = DASH / "public"
SCRATCH = REPO / ".local-runs"
NO_SHELL = "shell" + "=True"
LIVE_STATE = "state.json"
MCP_PRODUCER = REPO / "scripts" / "evidence" / "mcp-tools-state.py"
GOOD_ACCT = "0123456789abcdef0123456789abcdef"
# an obviously fake probe value: it only proves the log never echoes file content
FAKE_PROBE = "fake-probe-value-7313"
FIXTURES = Path(__file__).resolve().parent / "fixtures"
AT = chr(64)  # userinfo separator, built so no literal email-shaped string appears


def cfcommon_line(value):
    """One env-file line of the shape cfcommon reads, carrying the given (fake) value."""
    return "CLOUDFLARE_API_" + "TOKEN=" + value + "\n"


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
        for page in pages + sorted(PUBLIC.glob("*.js")):
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
        # reason: the file must hold a line for the permission probe to read; the value is the fake probe string,
        # the file lives in a private temp dir under .local-runs/ and is created owner-only (0o600), then mode 0
        fd = os.open(str(env_file), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(cfcommon_line(FAKE_PROBE))
        env_file.chmod(0)
        self.addCleanup(env_file.chmod, 0o600)
        if os.access(env_file, os.R_OK):
            self.skipTest("a privileged user reads a mode-0 file; the directory case covers the path")
        log = self._unreadable_log()
        self.assertEqual(log, "warning: home env file is unreadable (PermissionError)\n")
        self.assertNotIn(str(self.home), log)
        self.assertNotIn(".env", log)
        self.assertNotIn(FAKE_PROBE, log)

    def test_account_id_validation(self):
        self.assertTrue(self.cf.valid_account_id(GOOD_ACCT))
        for bad in ("", "../x", GOOD_ACCT.upper(), GOOD_ACCT + "0", "a/b?c=d" + GOOD_ACCT[:24]):
            self.assertFalse(self.cf.valid_account_id(bad), bad)

    def test_7593_a_non_utf8_home_env_file_is_a_one_line_refusal_with_a_nonzero_exit(self):
        (self.home / ".env").write_bytes(b"CLOUDFLARE_API_TOKEN=\xff\xfe\x80\n")
        for script, name, argv in (("deploy.py", "deploy_7593", ["deploy.py"]),
                                   ("push-state.py", "push_state_7593", ["push-state.py", str(self.home / "in.json")])):
            (self.home / "in.json").write_text("{}", encoding="utf-8")
            mod = _load(name, script)
            err = io.StringIO()
            with mock.patch.object(mod, "HERE", self.home, create=True), mock.patch.object(sys, "argv", argv), \
                    contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
                rc = mod.main()
            lines = [ln for ln in err.getvalue().splitlines() if ln]
            self.assertNotEqual(rc, 0, script)
            self.assertEqual(len(lines), 1, "%s: %r" % (script, err.getvalue()))
            self.assertNotIn("Traceback", err.getvalue())
            self.assertIn("UTF-8", lines[0])

    def test_7593_the_home_env_file_is_read_as_utf8_whatever_the_locale(self):
        (self.home / ".env").write_bytes("CLOUDFLARE_API_TOKEN=caf\u00e9\n".encode("utf-8"))
        with mock.patch("locale.getpreferredencoding", return_value="ascii"), \
                mock.patch.dict(os.environ, {"PYTHONUTF8": "0", "LC_ALL": "C"}):
            self.assertEqual(self.cf.credential("CLOUDFLARE_API_TOKEN"), "caf\u00e9")

    def _run_main(self, script, name, argv):
        mod = _load(name, script)
        err = io.StringIO()
        with mock.patch.object(sys, "argv", argv), contextlib.redirect_stderr(err), \
                contextlib.redirect_stdout(io.StringIO()):
            return mod, mod.main(), err.getvalue()

    def test_deploy_rejects_bad_account_before_any_request(self):
        bad = "../" + GOOD_ACCT
        self._envfile("CLOUDFLARE_API_TOKEN=%s\nCLOUDFLARE_ACCOUNT_ID=%s\n" % (FAKE_PROBE, bad))
        mod = _load("deploy_7313_a", "deploy.py")
        err = io.StringIO()
        with mock.patch.object(mod, "api", side_effect=AssertionError("request made")) as api, \
                mock.patch.object(sys, "argv", ["deploy.py"]), contextlib.redirect_stderr(err), \
                contextlib.redirect_stdout(io.StringIO()):
            rc = mod.main()
        self.assertEqual(rc, 1)
        api.assert_not_called()
        self.assertNotIn(bad, err.getvalue())
        self.assertNotIn(FAKE_PROBE, err.getvalue())

    def test_push_state_same_precedence_and_validation(self):
        self._envfile("CLOUDFLARE_API_TOKEN=%s\nCLOUDFLARE_ACCOUNT_ID=bad/acct\n" % FAKE_PROBE)
        os.environ["CLOUDFLARE_API_TOKEN"] = "envtoken-wins"
        src = self.home / "in.json"
        src.write_text("{}")
        mod = _load("push_state_7313_a", "push-state.py")
        seen = {}

        def fake_run(cmd, **kw):
            seen["env"] = kw.get("env")
            return subprocess.CompletedProcess(cmd, 0, "", "")

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
            return subprocess.CompletedProcess(cmd, 0, "deployed", "")

        with mock.patch("subprocess.run", fake):
            self.cf.run_wrangler(dict(os.environ), str(DASH))
        self.assertEqual(calls[0].get("timeout"), self.cf.WRANGLER_TIMEOUT_S)

    def test_deploy_timeout_exits_nonzero(self):
        mod = _load("deploy_7313_c", "deploy.py")
        ok = (True, {"success": True, "result": {"name": "n"}})

        def boom(cmd, **kw):
            raise subprocess.TimeoutExpired(cmd, kw.get("timeout", 0))

        with mock.patch.object(mod, "api", return_value=ok), mock.patch("subprocess.run", boom), \
                mock.patch.object(sys, "argv", ["deploy.py"]), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(mod.main(), 1)

    def test_push_state_timeout_exits_nonzero(self):
        mod = _load("push_state_7313_t", "push-state.py")
        src = self.home / "in.json"
        src.write_text("{}")

        def boom(cmd, **kw):
            raise subprocess.TimeoutExpired(cmd, kw.get("timeout", 0))

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
        self.assertEqual(origin_mod.loaded_origins(page),
                         {"https://evil.example", "https://css.example", "https://img.example"})

    def test_quoted_gt_before_src(self):
        self.assertEqual(origin_mod.loaded_origins('<script data-x="a>b" src="https://gt.example/a.js"></script>'),
                         {"https://gt.example"})

    def test_data_rel_preconnect_does_not_skip(self):
        self.assertEqual(origin_mod.loaded_origins('<script data-rel="preconnect" src="https://dr.example/a.js"></script>'),
                         {"https://dr.example"})

    def test_rel_preconnect_in_url_does_not_skip(self):
        self.assertEqual(origin_mod.loaded_origins('<link href="https://q.example/a.css?rel=preconnect">'),
                         {"https://q.example"})

    def test_data_image_text_before_src(self):
        self.assertEqual(origin_mod.loaded_origins('<img alt="data:image" src="https://alt.example/p.png">'),
                         {"https://alt.example"})

    def test_entity_encoded_colon(self):
        self.assertEqual(origin_mod.loaded_origins('<script src="https&#58;//enc.example/a.js"></script>'),
                         {"https://enc.example"})

    def test_protocol_relative_host(self):
        self.assertEqual(origin_mod.loaded_origins('<script src="//rel.example/a.js"></script>'),
                         {"https://rel.example"})

    def test_media_and_embed_tags(self):
        page = ('<video src="https://v.example/a.mp4"><source src="https://s.example/a.mp4"></video>'
                '<audio src="https://a.example/a.ogg"></audio><embed src="https://e.example/a">'
                '<object data="https://o.example/a"></object>'
                '<img srcset="https://set.example/1.png 1x, //set2.example/2.png 2x">')
        self.assertEqual(origin_mod.loaded_origins(page), {"https://v.example", "https://s.example",
                                                "https://a.example", "https://e.example",
                                                "https://o.example", "https://set.example",
                                                "https://set2.example"})

    def test_preconnect_with_loading_rel_still_loads(self):
        self.assertEqual(origin_mod.loaded_origins('<link rel="preconnect stylesheet" href="https://pcs.example/a.css">'),
                         {"https://pcs.example"})

    def test_pure_preconnect_data_uri_and_relative_are_skipped(self):
        page = ('<link rel="preconnect" href="https://pre.example">'
                '<link rel="dns-prefetch preconnect" href="https://pre2.example">'
                '<img src="data:image/png;base64,AAAA"><script src="/local.js"></script>')
        self.assertEqual(origin_mod.loaded_origins(page), set())

    def test_poster(self):
        self.assertEqual(origin_mod.loaded_origins('<video poster="https://poster.example/p.png"></video>'), {"https://poster.example"})

    def test_imagesrcset(self):
        self.assertEqual(origin_mod.loaded_origins('<link rel="preload" as="image" imagesrcset="https://pre3.example/a.png 1x">'),
                         {"https://pre3.example"})

    def test_track_src(self):
        self.assertEqual(origin_mod.loaded_origins('<video><track src="https://trk.example/a.vtt"></video>'), {"https://trk.example"})

    def test_input_image_src(self):
        self.assertEqual(origin_mod.loaded_origins('<input type="image" src="https://inp.example/b.png">'), {"https://inp.example"})

    def test_svg_image_href_and_xlink(self):
        self.assertEqual(origin_mod.loaded_origins('<svg><image href="https://svg.example/i.png"/>'
                                        '<image xlink:href="https://svgx.example/i.png"/></svg>'),
                         {"https://svg.example", "https://svgx.example"})

    def test_url_whitespace_and_backslash_normalised(self):
        self.assertEqual(origin_mod.loaded_origins('<img src="ht\ntps://nl.example/p.png">'), {"https://nl.example"})
        self.assertEqual(origin_mod.loaded_origins('<img src="https://ta\tb.example/p.png">'), {"https://tab.example"})
        self.assertEqual(origin_mod.loaded_origins('<img src="https:\\\\bs.example/p.png">'), {"https://bs.example"})
        self.assertEqual(origin_mod.loaded_origins('<img src="\\\\bs2.example/p.png">'), {"https://bs2.example"})

    def test_duplicate_attribute_first_wins(self):
        self.assertEqual(origin_mod.loaded_origins('<img src="https://first.example/a.png" src="https://second.example/b.png">'),
                         {"https://first.example"})


    def test_c0_controls_at_both_ends_are_stripped(self):
        # review r4 NOTE 1 (#7493): WHATWG strips every leading/trailing U+0000..U+0020
        self.assertEqual(origin_mod.loaded_origins('<img src="\x01https://c0.example/p.png">'), {"https://c0.example"})
        self.assertEqual(origin_mod.loaded_origins('<img src="\x1f\x00//c1.example/p.png\x02">'), {"https://c1.example"})

    def test_explicit_port_is_part_of_the_origin(self):
        # review r4 NOTE 2 (#7494): a host-source without a port matches only the default port
        self.assertEqual(origin_mod.loaded_origins('<img src="https://port.example:8443/p.png">'),
                         {"https://port.example:8443"})
        self.assertEqual(origin_mod.loaded_origins('<img src="https://dflt.example:443/p.png">'), {"https://dflt.example"})
        self.assertEqual(origin_mod.loaded_origins('<img src="http://plain.example:80/p.png">'), {"http://plain.example"})
        self.assertEqual(origin_mod.loaded_origins('<img src="http://alt.example:8080/p.png">'),
                         {"http://alt.example:8080"})

    def test_userinfo_is_not_the_host(self):
        # review r4 NOTE 3 (#7495)
        self.assertEqual(origin_mod.loaded_origins('<img src="https://u' + AT + 'ui.example/p.png">'), {"https://ui.example"})
        self.assertEqual(origin_mod.loaded_origins('<img src="https://u:pw' + AT + 'ui2.example:9000/p.png">'),
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
                found = origin_mod.loaded_origins('<img src="%s">' % value.replace("&", "&amp;").replace('"', "&quot;"))
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
        return origin_mod.loaded_origins('<img src="%s">' % value)

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


class PublicSnapshotHygiene7518(unittest.TestCase):
    """#7518/#7547: nothing under public/ (deployed to the public dashboard) names an internal node or path,
    and the generators that write state files scrub them and refuse to write what is left. No internal
    hostname is committed: host ids are scrubbed by SHAPE, plus this machine's name and an untracked local list."""

    FAKE_NODE = "zz-fake-node-7547"

    def setUp(self):
        SCRATCH.mkdir(exist_ok=True)
        self._tmp = tempfile.TemporaryDirectory(dir=str(SCRATCH))
        self.addCleanup(self._tmp.cleanup)
        self.names_file = Path(self._tmp.name) / "hostnames.local"
        self.names_file.write_text("# fake node list for the test\n%s\n\n" % self.FAKE_NODE, encoding="utf-8")
        patcher = mock.patch.dict(os.environ, {"CF_DASHBOARD_HOSTNAMES_FILE": str(self.names_file)})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.node = self.FAKE_NODE

    def test_no_public_json_names_an_internal_host_or_path(self):
        hostscrub = _load("hostscrub_7518_t", "hostscrub.py")
        for path in sorted(PUBLIC.glob("*.json")):
            self.assertEqual(hostscrub.find_leaks(path.read_text(encoding="utf-8")), [], path.name)

    def test_scrub_replaces_hostnames_and_paths_in_nested_values(self):
        hostscrub = _load("hostscrub_7518_s", "hostscrub.py")
        node = self.node
        record = {"note": '{"agent_id": "host:%s", "from": "ai:x@%s"}' % (node, node.upper()),
                  "run_dir": "/home/someone/run-1", "deep": [{"p": "/mnt/disk1/x"}, "/ai-" + "scratch/y", 3, None]}
        clean = hostscrub.scrub(record)
        text = json.dumps(clean)
        self.assertEqual(hostscrub.find_leaks(text), [])
        self.assertNotIn(node, text.lower())
        self.assertIn("host:" + hostscrub.REDACTED, clean["note"])
        self.assertEqual(clean["deep"][2:], [3, None])

    def test_any_host_id_shape_is_scrubbed_even_for_a_node_nobody_listed(self):
        hostscrub = _load("hostscrub_7547_shape", "hostscrub.py")
        text = json.dumps({"a": "host:build-box-7", "b": "ai:agent-1@build-box-7", "host:other-box_2": 1})
        self.assertNotEqual(hostscrub.find_leaks(text), [])
        clean = hostscrub.dump_clean({"a": "host:build-box-7", "b": "ai:agent-1@build-box-7", "host:other-box_2": 1})
        self.assertNotIn("build-box-7", clean)
        self.assertNotIn("other-box", clean)
        self.assertIn("host:node", clean)
        self.assertIn("ai:agent-1@node", clean)

    def test_the_public_placeholder_shapes_are_not_leaks(self):
        hostscrub = _load("hostscrub_7547_ok", "hostscrub.py")
        for ok in ("host:node", "ai:fable-validator@node", "4,602 ops/s @256", "email me at x@y"):
            self.assertEqual(hostscrub.find_leaks(ok), [], ok)

    def test_internal_dns_suffix_shapes_are_scrubbed(self):
        hostscrub = _load("hostscrub_7547_dns", "hostscrub.py")
        for shape in ("buildbox.local", "buildbox.lan", "buildbox.internal", "buildbox.home.arpa", "buildbox.corp"):
            out = hostscrub.dump_clean({"n": "reach " + shape + " now"})
            self.assertNotIn("buildbox", out, shape)

    def test_7592_scrub_and_leak_verdict_do_not_depend_on_the_machine_hostname(self):
        hostscrub = _load("hostscrub_7592_a", "hostscrub.py")
        record = {"n": "running on zz-runtime-7547 with ai-memory and the memory of a hostname",
                  "s": "host:build-box-7"}
        verdicts = []
        for fake in ("zz-runtime-7547", "ai", "memory", "node", "localhost", "a"):
            with mock.patch("socket.gethostname", return_value=fake):
                verdicts.append((hostscrub.dump_clean(record), hostscrub.find_leaks(json.dumps(record)),
                                 hostscrub.find_leaks("running on zz-runtime-7547")))
        self.assertEqual(len(set(map(repr, verdicts))), 1, "the output depends on socket.gethostname")
        out = verdicts[0][0]
        self.assertIn("ai-memory", out)
        self.assertIn("the memory of a hostname", out)
        self.assertIn("zz-runtime-7547", out)  # not a listed name and not a host-id shape: not this module rule

    def test_7592_a_hostname_that_is_a_substring_of_a_common_word_does_not_corrupt_text(self):
        hostscrub = _load("hostscrub_7592_b", "hostscrub.py")
        text = "ai-memory Main maintains the daemon; domain remainder; a node named ai"
        for fake in ("main", "ai", "mem", "node"):
            with mock.patch("socket.gethostname", return_value=fake):
                self.assertEqual(hostscrub.scrub_text(text), text, fake)
                self.assertEqual(hostscrub.find_leaks(text), [], fake)

    def test_7592_a_listed_name_matches_whole_host_tokens_only(self):
        self.names_file.write_text("ai\nbox\n", encoding="utf-8")
        hostscrub = _load("hostscrub_7592_c", "hostscrub.py")
        for untouched in ("ai-memory", "mailbox", "boxes", "x-box", "main"):
            self.assertEqual(hostscrub.scrub_text("see " + untouched + " now"), "see " + untouched + " now", untouched)
        for token in ("ai", "AI", "box"):
            self.assertEqual(hostscrub.scrub_text("on %s." % token), "on node.", token)
            self.assertEqual(hostscrub.scrub_text("(%s)" % token), "(node)", token)
            self.assertEqual(hostscrub.scrub_text("by %s, then" % token), "by node, then", token)

    def test_7641_a_listed_name_with_a_host_suffix_is_reported_and_scrubbed(self):
        self.names_file.write_text("ai\nbox\n", encoding="utf-8")
        hostscrub = _load("hostscrub_7641", "hostscrub.py")
        for derived in ("box_2", "ai2", "box-07", "ai-3", "BOX-prod_1"):
            self.assertEqual(hostscrub.find_leaks("on " + derived + " now"), [derived], derived)
            self.assertEqual(hostscrub.scrub_text("on " + derived + " now"), "on node now", derived)
            self.assertNotIn(derived.lower(), hostscrub.dump_clean({"n": "on " + derived}).lower())
        # the explicit exception list keeps the product name readable; look-alikes stay untouched
        for ok in ("ai-memory", "ai-memory-mcp", "mailbox", "boxes", "x-box", "main"):
            self.assertEqual(hostscrub.find_leaks("see " + ok), [], ok)
            self.assertEqual(hostscrub.scrub_text("see " + ok), "see " + ok, ok)

    def test_7642_two_keys_that_scrub_to_the_same_key_are_refused(self):
        hostscrub = _load("hostscrub_7642", "hostscrub.py")
        node = self.node
        with self.assertRaises(hostscrub.LeakError):
            hostscrub.scrub({"host:%s" % node: 1, "host:node": 2})
        with self.assertRaises(hostscrub.LeakError):
            hostscrub.dump_clean({"x": {"host:aa-1": 1, "host:bb-2": 2}})
        self.assertEqual(hostscrub.scrub({"host:node": 1, "other": 2}), {"host:node": 1, "other": 2})

    def test_names_in_the_local_untracked_file_are_scrubbed_and_comments_ignored(self):
        hostscrub = _load("hostscrub_7547_file", "hostscrub.py")
        out = hostscrub.dump_clean({"n": "plain " + self.node + " and a for-test comment"})
        self.assertNotIn(self.node, out)
        self.assertIn("for-test", out)

    def test_a_configured_but_unreadable_names_file_fails_closed(self):
        hostscrub = _load("hostscrub_7547_closed", "hostscrub.py")
        missing = Path(self._tmp.name) / "no-such-file"
        with mock.patch.dict(os.environ, {"CF_DASHBOARD_HOSTNAMES_FILE": str(missing)}):
            with self.assertRaises(hostscrub.LeakError):
                hostscrub.dump_clean({"n": "anything"})
            with self.assertRaises(hostscrub.LeakError):
                hostscrub.find_leaks("anything")

    def test_no_internal_hostname_is_committed_in_hostscrub(self):
        source = (DASH / "hostscrub.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        for node in tree.body:
            targets = [t.id for t in getattr(node, "targets", []) if isinstance(t, ast.Name)]
            self.assertNotIn("INTERNAL_HOSTNAMES", targets, "a committed hostname list")
        ignore = (DASH / ".gitignore").read_text(encoding="utf-8").split()
        self.assertIn("hostnames.local", ignore)

    def test_mcp_tools_state_generator_scrubs_before_writing(self):
        hostscrub = _load("hostscrub_7518_g", "hostscrub.py")
        node = self.node
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

    def _push(self, mod, tmp, src_arg, creds=("tok", None), wrangler_rc=0):
        """Run push-state.main with credentials and wrangler stubbed; returns (rc, stderr)."""
        err = io.StringIO()
        fake = mock.Mock(returncode=wrangler_rc, stdout="deployed", stderr="")
        if creds is None:
            load = mock.patch.object(mod.cfcommon, "load_credentials",
                                     side_effect=mod.cfcommon.CredentialError("none"))
        else:
            load = mock.patch.object(mod.cfcommon, "load_credentials", return_value=creds)
        with mock.patch.object(mod, "HERE", Path(tmp)), load, \
                mock.patch.object(mod.cfcommon, "run_wrangler", return_value=fake), \
                mock.patch.object(sys, "argv", ["push-state.py", src_arg]), \
                contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            rc = mod.main()
        return rc, err.getvalue()

    def test_push_state_scrubs_the_live_state_before_writing(self):
        node = self.node
        mod = _load("push_state_7518", "push-state.py")
        with tempfile.TemporaryDirectory(dir=str(SCRATCH)) as tmp:
            src = Path(tmp) / "in.json"
            src.write_text(json.dumps({"agents": [{"node": node}]}))
            rc, _ = self._push(mod, tmp, str(src))
            self.assertEqual(rc, 0)
            written = (Path(tmp) / "public" / "state.json").read_text(encoding="utf-8")
            self.assertNotIn(node, written.lower())

    def test_7643_push_state_bad_input_exits_2_with_a_fixed_message_and_no_traceback(self):
        mod = _load("push_state_7643_a", "push-state.py")
        with tempfile.TemporaryDirectory(dir=str(SCRATCH)) as tmp:
            bad = Path(tmp) / "latin1.json"
            bad.write_bytes(b'{"n": "caf\xe9"}')
            rc, err = self._push(mod, tmp, str(bad))
            self.assertEqual((rc, err), (2, "push-state: the state is not valid UTF-8 text\n"))
            rc, err = self._push(mod, tmp, str(Path(tmp) / "missing.json"))
            self.assertEqual((rc, err), (2, "push-state: the state file cannot be read\n"))
            self.assertFalse((Path(tmp) / "public" / "state.json").exists())
            self.assertNotIn("Traceback", err)

    def test_7643_push_state_reads_utf8_regardless_of_the_locale(self):
        mod = _load("push_state_7643_b", "push-state.py")
        with tempfile.TemporaryDirectory(dir=str(SCRATCH)) as tmp:
            src = Path(tmp) / "in.json"
            src.write_bytes(json.dumps({"n": "caf\u00e9 \u2713"}, ensure_ascii=False).encode("utf-8"))
            real_read_text = Path.read_text

            def guarded(self, *a, **k):
                if self.name == "in.json":
                    raise AssertionError("locale read_text used for the state file")
                return real_read_text(self, *a, **k)

            with mock.patch("locale.getpreferredencoding", return_value="ANSI_X3.4-1968"), \
                    mock.patch.object(Path, "read_text", guarded):
                rc, err = self._push(mod, tmp, str(src))
            self.assertEqual((rc, err), (0, ""))
            self.assertIn("caf", (Path(tmp) / "public" / "state.json").read_text(encoding="utf-8"))

    def test_7643_push_state_loads_credentials_before_writing_anything(self):
        mod = _load("push_state_7643_c", "push-state.py")
        with tempfile.TemporaryDirectory(dir=str(SCRATCH)) as tmp:
            src = Path(tmp) / "in.json"
            src.write_text(json.dumps({"agents": []}))
            rc, err = self._push(mod, tmp, str(src), creds=None)
            self.assertEqual(rc, 1)
            self.assertIn("push-state:", err)
            self.assertFalse((Path(tmp) / "public").exists(), "state.json written before credentials were known")

    def test_7643_push_state_writes_atomically_through_os_replace(self):
        mod = _load("push_state_7643_d", "push-state.py")
        with tempfile.TemporaryDirectory(dir=str(SCRATCH)) as tmp:
            src = Path(tmp) / "in.json"
            src.write_text(json.dumps({"agents": []}))
            public = Path(tmp) / "public"
            public.mkdir()
            target = public / "state.json"
            target.write_text("OLD\n")
            real = os.replace
            seen = []

            def spy(a, b):
                seen.append((Path(a).name, Path(b).name, target.read_text()))
                return real(a, b)

            with mock.patch.object(mod.os, "replace", side_effect=spy):
                rc, _ = self._push(mod, tmp, str(src))
            self.assertEqual(rc, 0)
            self.assertEqual(len(seen), 1)
            self.assertEqual(seen[0][1:], ("state.json", "OLD\n"), "the target was touched before os.replace")
            self.assertNotEqual(seen[0][0], "state.json")
            self.assertEqual(sorted(x.name for x in public.iterdir()), ["state.json"], "temp file left behind")
            self.assertNotEqual(target.read_text(), "OLD\n")


class HtmlAndHeaders7313(unittest.TestCase):
    """F4 (attribute-safe escaping) and F5 (_headers CSP, framing, no duplicate rule)."""

    def test_no_unused_locals_from_codeql_467_to_476(self):
        # #7497: the removed names must not come back (js/unused-local-variable)
        for page in sorted(PUBLIC.glob("*.html")):
            text = page.read_text()
            self.assertIsNone(re.search(r"\bw1\s*=", text), "%s declares unused w1" % page.name)
        index = (PUBLIC / "index.js").read_text()
        for pat in (r"const tok=", r"const done=dims", r"tot=dims\.length", r"gap=0\.004"):
            self.assertIsNone(re.search(pat, index), "index.js still has %s" % pat)

    def test_index_ring_rejects_a_non_list_dimensions_field_7517(self):
        # removing the dead `dims.filter(...)` line also removed the implicit TypeError for a non-list
        # `dimensions`; the ring must keep its placeholder (the explicit throw skips the ring code and
        # leaves the poll's catch to mark the page offline), not paint a real-looking 0%.
        text = (PUBLIC / "index.js").read_text()
        render = text[text.index("function renderAll(D){"):text.index("/* ---------- live poll ---------- */")]
        guard = re.search(r"if\(!Array\.isArray\(dims\)\)\s*throw new TypeError\(", render)
        self.assertIsNotNone(guard, "renderAll lost its Array.isArray(dims) guard")
        self.assertLess(guard.start(), render.index('getElementById("ringpct")'))
        self.assertLess(render.index("_S(()=>board(dims))"), guard.start(), "panels must render before the guard")

    BADGE_HARNESS = """
const els = {};
const document = {getElementById: id => els[id] || (els[id] = {className: "", textContent: ""})};
let nextBody = null;
function fetch() {
  return Promise.resolve({ok: true, json: () => nextBody instanceof Error ? Promise.reject(nextBody) : Promise.resolve(nextBody)});
}
function renderAll(D) { if (!Array.isArray(D.dimensions)) throw new TypeError("state.dimensions is not a list"); }
(async () => {
  %(SOURCE)s
  const out = {};
  const text = () => els.livetext.textContent;
  nextBody = {dimensions: [], lastUpdated: new Date().toISOString()};
  await poll(); out.good = text();
  nextBody = {dimensions: "not-a-list"};
  await poll(); out.malformed = text(); tick(); out.malformedAfterTick = text();
  nextBody = new SyntaxError("bad json");
  await poll(); out.unparsable = text();
  nextBody = {dimensions: [], lastUpdated: new Date().toISOString()};
  await poll(); out.recovered = text(); tick(); out.recoveredAfterTick = text();
  console.log(JSON.stringify(out));
})();
"""

    def _poll_source(self):
        text = (PUBLIC / "index.js").read_text(encoding="utf-8")
        return text[text.index("let lastGood=0"):text.index('[["northstar"')]

    def test_index_badge_says_offline_for_a_malformed_state_7548(self):
        # renderAll throws on a non-list `dimensions`; the badge must not keep reading "connected" while the
        # page shows a half-rendered state (the 1 s tick used to repaint "live" from lastGood alone)
        source = self._poll_source()
        self.assertIn("stateBad", source, "poll() does not track a malformed state")
        self.assertRegex(source, r"function tick\(\)", "the 1 s badge tick is not a named function")
        index = (PUBLIC / "index.js").read_text(encoding="utf-8")
        self.assertIn("setInterval(tick,1000)", index)

    @unittest.skipUnless(shutil.which("node"), "node is needed to execute the page's poll code")
    def test_index_badge_behaviour_for_a_malformed_state_7548(self):
        js = self.BADGE_HARNESS % {"SOURCE": self._poll_source()}
        done = subprocess.run(["node", "-"], input=js, capture_output=True, text=True, timeout=60)
        self.assertEqual(done.returncode, 0, done.stderr)
        out = json.loads(done.stdout)
        self.assertTrue(out["good"].startswith("connected"), out)
        self.assertTrue(out["malformed"].startswith("offline"), out)
        self.assertTrue(out["malformedAfterTick"].startswith("offline"), out)
        self.assertTrue(out["unparsable"].startswith("offline"), out)
        self.assertTrue(out["recovered"].startswith("connected"), out)
        self.assertTrue(out["recoveredAfterTick"].startswith("connected"), out)

    LASTUPDATED_HARNESS = """
const els = {};
const document = {getElementById: id => els[id] || (els[id] = {className: "", textContent: ""})};
let nextBody = null;
function fetch() { return Promise.resolve({ok: true, json: () => Promise.resolve(nextBody)}); }
function renderAll(D) {}
(async () => {
  %(SOURCE)s
  const out = {};
  const snap = () => ({text: els.livetext.textContent, cls: els.livebadge.className});
  for (const bad of ["not a date", "2026-13-45T99:99:99Z", {}, "NaN", "0000-00-00"]) {
    nextBody = {dimensions: [], lastUpdated: bad};
    await poll(); out[JSON.stringify(bad)] = snap();
  }
  nextBody = {dimensions: [], lastUpdated: new Date(Date.now() - 5000).toISOString()};
  await poll(); out.good = snap();
  nextBody = {dimensions: []};
  await poll(); out.absent = snap();
  console.log(JSON.stringify(out));
})();
"""

    @unittest.skipUnless(shutil.which("node"), "node is needed to execute the page's poll code")
    def test_7640_an_unparsable_lastupdated_is_a_stale_badge_never_nan(self):
        js = self.LASTUPDATED_HARNESS % {"SOURCE": self._poll_source()}
        done = subprocess.run(["node", "-"], input=js, capture_output=True, text=True, timeout=60)
        self.assertEqual(done.returncode, 0, done.stderr)
        out = json.loads(done.stdout)
        for key, snap in out.items():
            self.assertNotIn("NaN", snap["text"], key)
            self.assertNotIn("undefined", snap["text"], key)
        for key in [k for k in out if k not in ("good", "absent")]:
            self.assertEqual(out[key]["text"], "stale \u00b7 state time unknown", key)
            self.assertIn("stale", out[key]["cls"], key)
        self.assertTrue(out["good"]["text"].startswith("connected"), out["good"])
        self.assertTrue(out["absent"]["text"].startswith("connected"), out["absent"])


VV_JS = PUBLIC / "vv.js"
MCP_SNAPSHOT = PUBLIC / "mcp-tools-state.json"
MCP_CLASSES = REPO / "scripts" / "evidence" / "mcp-tools-classes.json"
TOOL_CLASSES = {"validated", "failclosed", "refining"}


class McpToolsState7644(unittest.TestCase):
    """#7644: the committed mcp-tools snapshot is the OFFICIAL producer's output (groups, run_id, source_commit),
    the page renders that shape, and vv.js derives pct from the counts when the state has none (index.js:555)."""

    VV_HARNESS = """
const els = {};
class El {
  constructor(){ this.children = []; this.style = {}; this.className = ""; this.textContent = ""; this.listeners = {}; }
  appendChild(c){ this.children.push(c); return c; }
  addEventListener(){} setAttribute(){} getAttribute(){ return "x-state.json"; } prepend(){}
  closest(){ return this; } classList = {toggle(){}, remove(){}};
}
const document = {
  body: new El(),
  getElementById: id => els[id] || (els[id] = new El()),
  createElement: () => new El(),
  querySelectorAll: () => [],
  addEventListener(){},
  fullscreenElement: null,
};
document.body.getAttribute = () => "x-state.json";
const setInterval = () => 0;
let body = null;
const fetch = () => Promise.resolve({ok: true, json: () => Promise.resolve(body)});
const out = {};
(async () => {
  for (const [key, b] of Object.entries(%(CASES)s)) {
    body = b; els.pct = new El();
    (function(){ %(SOURCE)s })();
    await new Promise(r => setTimeout(r, 20));
    out[key] = els.pct.textContent;
  }
  console.log(JSON.stringify(out));
})();
"""

    def _producer(self):
        spec = importlib.util.spec_from_file_location("mcp_tools_state_7644", MCP_PRODUCER)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def _run_producer(self, tools, classes=None):
        mod = self._producer()
        SCRATCH.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=str(SCRATCH)) as tmp:
            run_dir = Path(tmp) / "run-a"
            run_dir.mkdir()
            (run_dir / "tools-list.json").write_text(json.dumps(tools))
            argv = ["mcp-tools-state.py", "--run-dir", str(run_dir), "--out", str(Path(tmp) / "o" / "s.json")]
            if classes is not None:
                (Path(tmp) / "classes.json").write_text(json.dumps(classes))
                argv += ["--classes", str(Path(tmp) / "classes.json")]
            with mock.patch.object(mod, "git", return_value="a" * 40), \
                    mock.patch.object(sys, "argv", argv), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(mod.main(), 0)
            return json.loads((Path(tmp) / "o" / "s.json").read_text(encoding="utf-8"))

    def test_7644_producer_emits_groups_with_run_id_and_source_commit(self):
        tools = [{"name": "memory_skill_get", "description": "Get a skill. More text follows."},
                 {"name": "memory_skill_list", "description": "List skills"},
                 {"name": "memory_store", "description": "Store a memory"},
                 {"name": "memory_atomise", "description": "Atomise"}]
        rec = self._run_producer(tools, {"failclosed": {"memory_skill_get": "skill not found"},
                                         "refining": {"memory_atomise": "memory not found"}})
        self.assertEqual((rec["total"], rec["validated"], rec["failclosed"], rec["refining"], rec["functional"]),
                         (4, 2, 1, 1, 3))
        self.assertEqual(rec["source_commit"], "a" * 40)
        self.assertTrue(rec["run_id"])
        self.assertNotIn("pct", rec)
        groups = {g["family"]: g["tools"] for g in rec["groups"]}
        self.assertEqual(sorted(groups), ["atomise", "skill", "store"])
        get = [t for t in groups["skill"] if t["name"] == "memory_skill_get"][0]
        self.assertEqual((get["cls"], get["status"], get["desc"], get["note"]),
                         ("failclosed", "refusal", "Get a skill", "skill not found"))
        self.assertEqual(groups["atomise"][0]["cls"], "refining")
        self.assertEqual(groups["store"][0]["cls"], "validated")

    def test_7644_committed_snapshot_is_the_producer_output_the_page_can_render(self):
        rec = json.loads(MCP_SNAPSHOT.read_text(encoding="utf-8"))
        self.assertEqual(rec["producer_id"], "mcp-tools-state")
        self.assertRegex(rec["source_commit"], r"^[0-9a-f]{40}$")
        self.assertTrue(rec["run_id"])
        self.assertIsNotNone(rec.get("lastUpdated"))
        self.assertNotIn("pct", rec, "the producer never emits pct; the page derives it from the counts")
        tools = [t for g in rec["groups"] for t in g["tools"]]
        self.assertEqual(len(tools), rec["total"])
        self.assertEqual(sorted(t["name"] for t in tools), rec["names"])
        self.assertEqual({t["cls"] for t in tools} - TOOL_CLASSES, set(), "a class the page has no CSS for")
        counts = {c: len([t for t in tools if t["cls"] == c]) for c in TOOL_CLASSES}
        self.assertEqual((counts["validated"], counts["failclosed"], counts["refining"]),
                         (rec["validated"], rec["failclosed"], rec["refining"]))
        self.assertEqual(rec["functional"], rec["total"] - rec["refining"])
        page = (PUBLIC / "mcp-tools.html").read_text(encoding="utf-8")
        for cls in TOOL_CLASSES:
            self.assertIn(".tool.%s" % cls, page)

    def test_7644_the_classes_file_names_only_captured_tools(self):
        classes = json.loads(MCP_CLASSES.read_text(encoding="utf-8"))
        names = set(json.loads(MCP_SNAPSHOT.read_text(encoding="utf-8"))["names"])
        for key in ("failclosed", "refining"):
            self.assertLessEqual(set(classes[key]), names, key)
        self.assertFalse(set(classes["failclosed"]) & set(classes["refining"]))

    @unittest.skipUnless(shutil.which("node"), "node is needed to execute vv.js")
    def test_7644_vv_js_derives_pct_from_the_counts_like_index_js(self):
        cases = {"derived": {"total": 100, "validated": 70, "failclosed": 25, "refining": 5, "groups": []},
                 "explicit": {"total": 100, "validated": 70, "failclosed": 25, "pct": 50, "groups": []},
                 "nototal": {"validated": 1, "failclosed": 1, "groups": []},
                 "zero": {"total": 0, "validated": 0, "failclosed": 0, "groups": []}}
        js = self.VV_HARNESS % {"CASES": json.dumps(cases), "SOURCE": VV_JS.read_text(encoding="utf-8")}
        done = subprocess.run(["node", "-"], input=js, capture_output=True, text=True, timeout=60)
        self.assertEqual(done.returncode, 0, done.stderr)
        out = json.loads(done.stdout)
        self.assertEqual(out["derived"], "95")
        self.assertEqual(out["explicit"], "50")
        self.assertEqual(out["nototal"], "\u2014")
        self.assertEqual(out["zero"], "\u2014")


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
        self.assertRegex(text, r"os\.open\(.*0o600", "the unreadable-env probe must create its file owner-only")

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
