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
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[3]
DASH = REPO / "infra" / "cf-dashboard"
PUBLIC = DASH / "public"
SCRATCH = REPO / ".local-runs"
NO_SHELL = "shell" + "=True"
LIVE_STATE = "state.json"
MCP_PRODUCER = REPO / "scripts" / "evidence" / "mcp-tools-state.py"
GOOD_ACCT = "0123456789abcdef0123456789abcdef"
SECRET_TOKEN = "tok-SENTINEL-VALUE-7313"


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


TAG_RE = re.compile(r"<(?:link|script|img|iframe)\b[^>]*>", re.IGNORECASE)
ORIGIN_RE = re.compile(r"https://[a-z0-9.-]+", re.IGNORECASE)
PRECONNECT_RE = re.compile(r"""rel\s*=\s*["']?preconnect""", re.IGNORECASE)


def loaded_origins(html):
    """External https origins a page loads, matched case-insensitively (HTML tag and
    attribute names are case-insensitive; origins are returned lower-cased)."""
    found = set()
    for tag in TAG_RE.findall(html):
        if PRECONNECT_RE.search(tag):
            continue
        head = re.split("data:image", tag, maxsplit=1, flags=re.IGNORECASE)[0]
        found.update(o.lower() for o in ORIGIN_RE.findall(head))
    return found


class LoadedOriginsCase7313(unittest.TestCase):
    """CodeQL py/bad-tag-filter: upper/mixed-case tags must not escape the CSP origin check."""

    def test_mixed_case_tags_are_detected(self):
        page = ('<SCRIPT SRC="https://Evil.Example/x.js"></SCRIPT>'
                '<Link REL="stylesheet" href="https://css.example/a.css">'
                '<IMG src="HTTPS://img.example/p.png">'
                '<LINK REL="PRECONNECT" href="https://pre.example">'
                '<Img src="DATA:IMAGE/png;base64,AAAA https://skip.example">')
        self.assertEqual(loaded_origins(page),
                         {"https://evil.example", "https://css.example", "https://img.example"})

    def test_old_case_sensitive_filter_misses_them(self):
        page = '<SCRIPT SRC="https://evil.example/x.js"></SCRIPT>'
        self.assertEqual(re.findall(r"<(?:link|script|img|iframe)\b[^>]*>", page), [])
        self.assertEqual(loaded_origins(page), {"https://evil.example"})


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

    def test_headers_csp_matches_loaded_origins(self):
        headers = (PUBLIC / "_headers").read_text()
        csp = re.search(r"Content-Security-Policy: (.*)", headers)
        self.assertIsNotNone(csp, "no Content-Security-Policy")
        csp = csp.group(1)
        self.assertIn("frame-ancestors 'none'", csp)
        self.assertIn("X-Frame-Options: DENY", headers)
        self.assertEqual(headers.count("/state.json"), 0, "redundant /state.json rule (covered by /*.json)")
        allowed = set(re.findall(r"https://[a-z0-9.-]+", csp))
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
