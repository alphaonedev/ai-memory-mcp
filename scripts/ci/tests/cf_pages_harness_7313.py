"""Headless-Chromium harness for the cf-dashboard pages (#7313); imported by the page behaviour tests.

The tracked public/ directory is served from the fake origin https://dash.example/ through request routing (no
network). Each response carries the page's real Content-Security-Policy lines from public/_headers (so a script the
policy blocks does not run here either) unless a test asks for none. A test overrides what any path answers
(`site.answer[path] = (status, body)`) to simulate a failing or hostile state. Everything outside the origin is
answered with an empty 200 so the Google Fonts links neither hang nor reach the network.
"""
import json
import mimetypes
from pathlib import Path

import cf_origin_7313 as origin_mod

PUBLIC = Path(__file__).resolve().parents[3] / "infra" / "cf-dashboard" / "public"
ORIGIN = "https://dash.example"
INIT_SCRIPT = ("window.__violations=[];document.addEventListener('securitypolicyviolation',function(e)"
               "{window.__violations.push(e.violatedDirective+' '+e.blockedURI)});")


def playwright_or_skip(testcase_class, unittest_module):
    """Start playwright and a chromium; raise unittest.SkipTest where either is missing."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        raise unittest_module.SkipTest("playwright is not installed")
    pw = sync_playwright().start()
    try:
        browser = pw.chromium.launch()
    except Exception as exc:  # no browser binary on this machine
        pw.stop()
        raise unittest_module.SkipTest("no chromium: %s" % exc)
    testcase_class._pw, testcase_class._browser = pw, browser


def stop(testcase_class):
    testcase_class._browser.close()
    testcase_class._pw.stop()


class Site:
    """One page open in chromium with routed responses."""

    def __init__(self, browser, with_csp=True, install_clock=False):
        self.answer = {}  # path -> (status, body) overriding the tracked file
        self.with_csp = with_csp
        self.errors = []
        self.page = browser.new_page()
        self.page.add_init_script(INIT_SCRIPT)
        self.page.on("pageerror", lambda exc: self.errors.append(str(exc)))
        self.page.route("**/*", self._route)
        if install_clock:
            self.page.clock.install()
        self._headers = (PUBLIC / "_headers").read_text(encoding="utf-8")

    def _file_for(self, path):
        if path == "/":
            path = "/index.html"
        candidate = PUBLIC / path.lstrip("/")
        if not candidate.is_file() and (PUBLIC / (path.lstrip("/") + ".html")).is_file():
            candidate = PUBLIC / (path.lstrip("/") + ".html")
        return candidate if candidate.is_file() and candidate.parent == PUBLIC else None

    def _route(self, route):
        url = route.request.url
        if not url.startswith(ORIGIN + "/"):
            route.fulfill(status=200, body="", content_type="text/css")
            return
        path = url[len(ORIGIN):].split("?", 1)[0].split("#", 1)[0]
        if path in self.answer:
            status, body = self.answer[path]
            route.fulfill(status=status, body=body, content_type="application/json" if path.endswith(".json") else "text/plain")
            return
        target = self._file_for(path)
        if target is None:
            route.fulfill(status=404, body="not found", content_type="text/plain")
            return
        headers = {"Content-Type": (mimetypes.guess_type(target.name)[0] or "text/plain") + "; charset=utf-8"}
        if target.suffix == ".js":
            headers["Content-Type"] = "text/javascript; charset=utf-8"
        if self.with_csp:
            lines = origin_mod.header_policies(self._headers, path)
            if lines:
                headers["Content-Security-Policy"] = ", ".join(lines)
        route.fulfill(status=200, body=target.read_bytes(), headers=headers)

    def goto(self, path):
        self.page.goto(ORIGIN + path)

    def settle(self, ms=400):
        self.page.wait_for_timeout(ms)

    def violations(self):
        return self.page.evaluate("window.__violations")

    def close(self):
        self.page.close()


def json_body(value):
    return json.dumps(value)
