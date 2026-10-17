"""CSP guard coverage table (#7589 #7590 #7591): same-origin, data: and blob: loads, CSS-initiated loads, inline
code, every policy a page gets.

Each row is (name, header policies, html, expected blocked). The expectations are written out by hand AND, where
headless Chromium is installed, re-derived from the browser itself: the guard must match Chromium on every row.
"""
import unittest

import cf_origin_7313 as origin_mod

PAGE_URL = "https://dash.example/"
DATA_PNG = "data:image/png;base64,AAAA"
SELF_IMG = "img-src 'self'"

# (name, header CSP lines, html body fragment, expected: some load is blocked)
CASES = (
    # --- #7589: same-origin, data: and blob: are checked against their own directive
    ("data img vs default-src self", ["default-src 'self'"], '<img src="%s">' % DATA_PNG, True),
    ("data img vs img-src data:", ["default-src 'none'; img-src data:"], '<img src="%s">' % DATA_PNG, False),
    ("data icon link vs img-src self", [SELF_IMG], '<link rel="icon" href="%s">' % DATA_PNG, True),
    ("data icon link vs img-src self data:", ["img-src 'self' data:"], '<link rel="icon" href="%s">' % DATA_PNG, False),
    ("same-origin script vs foreign script-src", ["script-src https://x.example"], '<script src="/a.js"></script>', True),
    ("same-origin script vs script-src self", ["script-src 'self'"], '<script src="/a.js"></script>', False),
    ("same-origin script vs default-src none", ["default-src 'none'"], '<script src="a.js"></script>', True),
    ("same-origin img vs img-src none", ["img-src 'none'"], '<img src="/a.png">', True),
    ("same-origin img vs img-src self", [SELF_IMG], '<img src="/a.png">', False),
    ("https scheme source admits same-origin", ["img-src https:"], '<img src="/a.png">', False),
    ("blob script vs script-src self", ["script-src 'self'"], '<script src="blob:https://dash.example/u"></script>', True),
    ("blob script vs script-src blob:", ["script-src blob:"], '<script src="blob:https://dash.example/u"></script>', False),
    # --- #7590: CSS-initiated loads
    ("style attr url foreign", ["img-src 'self'; style-src 'unsafe-inline'"],
     '<div style="background:url(https://evil.example/x.png)"></div>', True),
    ("style attr url foreign allowed", ["img-src https://ok.example; style-src 'unsafe-inline'"],
     '<div style="background:url(\'https://ok.example/x.png\')"></div>', False),
    ("style attr url same-origin vs img-src none", ["img-src 'none'; style-src 'unsafe-inline'"],
     '<div style="background-image:url(/x.png)"></div>', True),
    ("style attr url fragment loads nothing", ["img-src 'none'; style-src 'unsafe-inline'"],
     '<svg><rect style="fill:url(#g)"></rect></svg>', False),
    ("style import foreign", ["style-src 'self' 'unsafe-inline'"],
     '<style>@import "https://evil.example/a.css";</style>', True),
    ("style import url() allowed", ["style-src 'unsafe-inline' https://ok.example"],
     '<style>@import url(https://ok.example/a.css);</style>', False),
    ("style body url foreign img", ["img-src 'self'; style-src 'unsafe-inline'"],
     '<style>div{background:url(https://evil.example/i.png)}</style>', True),
    ("style body font-face foreign font", ["font-src 'self'; style-src 'unsafe-inline'"],
     '<style>@font-face{font-family:x;src:url(https://f.example/a.woff2)}</style>', True),
    ("style body font-face allowed font", ["font-src https://f.example; style-src 'unsafe-inline'"],
     '<style>@font-face{font-family:x;src:url(https://f.example/a.woff2)}</style>', False),
    ("body background attr foreign", ["img-src 'self'"], '<body background="https://evil.example/i.png"></body>', True),
    ("table background attr same-origin vs none", ["img-src 'none'"],
     '<table background="/i.png"><tr><td>x</td></tr></table>', True),
    ("table background attr allowed", [SELF_IMG], '<table background="/i.png"><tr><td>x</td></tr></table>', False),
    # --- inline code: script and style, element and attribute
    ("inline script vs script-src self", ["script-src 'self'"], "<script>window.q=1</script>", True),
    ("inline script vs unsafe-inline", ["script-src 'unsafe-inline'"], "<script>window.q=1</script>", False),
    ("inline handler vs script-src self", ["script-src 'self'"], '<button onclick="q()">x</button>', True),
    ("inline handler vs unsafe-inline", ["script-src 'unsafe-inline'"], '<button onclick="q()">x</button>', False),
    ("handler admitted by script-src-attr only", ["script-src 'self'; script-src-attr 'unsafe-inline'"],
     '<button onclick="q()">x</button>', False),
    ("element not admitted by script-src-attr", ["script-src 'self'; script-src-attr 'unsafe-inline'"],
     "<script>window.q=1</script>", True),
    ("inline style vs style-src self", ["style-src 'self'"], "<style>p{color:red}</style>", True),
    ("inline style vs unsafe-inline", ["style-src 'unsafe-inline'"], "<style>p{color:red}</style>", False),
    # --- #7591: every policy the page gets
    ("meta policy blocks", [SELF_IMG], '<meta http-equiv="Content-Security-Policy" content="img-src \'none\'">'
     '<img src="/a.png">', True),
    ("meta policy http-equiv case", [SELF_IMG], '<meta http-equiv="CONTENT-security-POLICY" content="img-src \'none\'">'
     '<img src="/a.png">', True),
    ("meta policy allows", [SELF_IMG], '<meta http-equiv="Content-Security-Policy" content="img-src \'self\'">'
     '<img src="/a.png">', False),
    ("second header line blocks", [SELF_IMG, "img-src 'none'"], '<img src="/a.png">', True),
    ("both header lines allow", [SELF_IMG, "img-src 'self' data:"], '<img src="/a.png">', False),
    ("a policy that does not mention the kind is no restriction", [SELF_IMG, "script-src 'none'"], '<img src="/a.png">', False),
)


def _meta_wrapped(html):
    """A whole document around the fragment: head-only elements (meta, link) go in the head, a body tag is the body."""
    if html.startswith("<body"):
        return "<!doctype html><html><head></head>%s</html>" % html
    if html.startswith(("<meta", "<link")):
        head, _, body = html.partition("<img")
        return "<!doctype html><html><head>%s</head><body>%s</body></html>" % (head, ("<img" + body) if body else "")
    return "<!doctype html><html><head></head><body>%s</body></html>" % html


class GuardTable7589(unittest.TestCase):
    def test_every_row_matches_the_hand_written_expectation(self):
        wrong = []
        for name, policies, html, expect in CASES:
            got = bool(origin_mod.blocked_loads(_meta_wrapped(html), policies))
            if got != expect:
                wrong.append((name, "guard blocked=%s expected=%s" % (got, expect)))
        self.assertEqual(wrong, [])

    def test_header_policies_collects_every_matching_rule_and_splits_commas(self):
        headers = ("/*\n  Content-Security-Policy: img-src 'self'\n  X-Frame-Options: DENY\n"
                   "/*.html\n  Content-Security-Policy: script-src 'none', style-src 'none'\n"
                   "/*.json\n  Content-Security-Policy: default-src 'none'\n")
        self.assertEqual(origin_mod.header_policies(headers, "/page.html"),
                         ["img-src 'self'", "script-src 'none'", "style-src 'none'"])
        self.assertEqual(origin_mod.header_policies(headers, "/state.json"),
                         ["img-src 'self'", "default-src 'none'"])
        self.assertEqual(origin_mod.header_policies(headers, "/"), ["img-src 'self'"])


class ChromiumAgreement7589(unittest.TestCase):
    """The guard must agree with Chromium on every table row (skipped where playwright is not installed)."""

    @classmethod
    def setUpClass(cls):
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            raise unittest.SkipTest("playwright is not installed")
        cls._pw = sync_playwright().start()
        try:
            cls._browser = cls._pw.chromium.launch()
        except Exception as exc:  # no browser binary on this machine
            cls._pw.stop()
            raise unittest.SkipTest("no chromium: %s" % exc)

    @classmethod
    def tearDownClass(cls):
        cls._browser.close()
        cls._pw.stop()

    def chromium_blocked(self, policies, html):
        page = self._browser.new_page()
        try:
            page.add_init_script("window.__v=[];document.addEventListener('securitypolicyviolation',"
                                 "function(e){window.__v.push(e.violatedDirective+' '+e.blockedURI)});")
            body = _meta_wrapped(html)

            def route(r):
                if r.request.url == PAGE_URL:
                    r.fulfill(status=200, body=body, headers={"Content-Security-Policy": ", ".join(policies),
                                                              "Content-Type": "text/html; charset=utf-8"})
                else:
                    ctype = {"script": "text/javascript", "stylesheet": "text/css"}.get(r.request.resource_type, "image/png")
                    r.fulfill(status=200, body="", content_type=ctype)

            page.route("**/*", route)
            page.goto(PAGE_URL)
            page.wait_for_timeout(250)
            return page.evaluate("window.__v")
        finally:
            page.close()

    def test_guard_equals_chromium_on_every_row(self):
        mismatch = []
        for name, policies, html, expect in CASES:
            browser = bool(self.chromium_blocked(policies, html))
            guard = bool(origin_mod.blocked_loads(_meta_wrapped(html), policies))
            if browser != guard:
                mismatch.append((name, "chromium blocked=%s guard blocked=%s" % (browser, guard)))
            self.assertEqual(browser, expect, "the hand-written expectation for %r is wrong" % name)
        self.assertEqual(mismatch, [])


if __name__ == "__main__":
    unittest.main()
