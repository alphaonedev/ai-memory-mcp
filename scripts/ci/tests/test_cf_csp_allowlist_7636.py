"""#7636 #7637 #7638 #7313: the CSP and page checker is a per-directive allowlist that fails closed.

Each row of REFUSE_POLICIES / REFUSE_PAGES is a shape the checker must REFUSE; the real shipped `_headers` and every
real page must be ACCEPTED. The checker may refuse safe input (a wildcard, an own-host source, an uncommon tag): the
tests pin that too, because a false refusal is the intended cost of having no emulation to get wrong."""
import unittest
from pathlib import Path

import cf_cdp_7313 as cdp
import cf_csp_allowlist_7313 as csp
import cf_origin_7313 as origin_mod

PUBLIC = Path(__file__).resolve().parents[3] / "infra" / "cf-dashboard" / "public"
HEADERS = (PUBLIC / "_headers").read_text(encoding="utf-8")


def shipped():
    refusals, value = csp.check_path(HEADERS, "/index.html")
    assert value is not None
    return value


def with_directive(name, tokens):
    """The shipped policy with one directive replaced (tokens None drops it)."""
    out = []
    for raw in shipped().split(";"):
        parts = raw.split()
        if parts and parts[0] == name:
            if tokens is not None:
                out.append(" ".join([name] + tokens))
        elif parts:
            out.append(raw.strip())
    return "; ".join(out)


def appended(directive):
    return shipped() + "; " + directive


# (row name, policy). Rows 7636/7637/7638 are the review shapes; the rest are the table's own edges.
REFUSE_POLICIES = (
    ("7636 script-src nonce plus unsafe-inline", with_directive("script-src", ["'self'", "'nonce-abc123'", "'unsafe-inline'"])),
    ("7636 script-src strict-dynamic plus unsafe-inline", with_directive("script-src", ["'strict-dynamic'", "'unsafe-inline'"])),
    ("7636 script-src hash", with_directive("script-src", ["'self'", "'sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='"])),
    ("7636 script-src-attr unsafe-inline", appended("script-src-attr 'unsafe-inline'")),
    ("7636 script-src-elem is not in the table", appended("script-src-elem 'self'")),
    ("7637 style-src nonce plus unsafe-inline", with_directive("style-src", ["'self'", "'nonce-abc123'", "'unsafe-inline'"])),
    ("7637 style-src hash", with_directive("style-src", ["'self'", "'sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='"])),
    ("7637 style-src-attr unsafe-inline", appended("style-src-attr 'unsafe-inline'")),
    ("7637 default-src unsafe-inline", with_directive("default-src", ["'self'", "'unsafe-inline'"])),
    ("7638 wildcard script source", with_directive("script-src", ["*"])),
    ("7638 wildcard image source", with_directive("img-src", ["*"])),
    ("7638 https: scheme source", with_directive("img-src", ["https:"])),
    ("7638 own-host source", with_directive("img-src", ["'self'", "https://dash.example"])),
    ("7638 wildcard host", with_directive("connect-src", ["https://*.example.com"])),
    ("7638 foreign script host", with_directive("script-src", ["'self'", "https://cdn.example.com"])),
    ("unsafe-eval", with_directive("script-src", ["'self'", "'unsafe-eval'"])),
    ("wasm-unsafe-eval", with_directive("script-src", ["'self'", "'wasm-unsafe-eval'"])),
    ("unsafe-hashes", with_directive("style-src", ["'self'", "'unsafe-hashes'"])),
    ("blob: image source", with_directive("img-src", ["'self'", "blob:"])),
    ("data: script source", with_directive("script-src", ["'self'", "data:"])),
    ("two policies in one value", shipped() + ", img-src 'none'"),
    ("duplicate script-src", appended("script-src 'self'")),
    ("duplicate directive in another case", appended("Script-Src 'self'")),
    ("unknown directive", appended("report-uri /csp")),
    ("upgrade-insecure-requests", appended("upgrade-insecure-requests")),
    ("sandbox", appended("sandbox")),
    ("worker-src is not in the table", appended("worker-src 'self'")),
    ("empty directive", appended("font-src")),
    ("missing require-trusted-types-for", with_directive("require-trusted-types-for", None)),
    ("missing trusted-types", with_directive("trusted-types", None)),
    ("missing base-uri", with_directive("base-uri", None)),
    ("missing object-src", with_directive("object-src", None)),
    ("missing script-src", with_directive("script-src", None)),
    ("trusted-types allow-duplicates", with_directive("trusted-types", ["dash", "'allow-duplicates'"])),
    ("trusted-types wildcard", with_directive("trusted-types", ["*"])),
    ("trusted-types second policy", with_directive("trusted-types", ["dash", "other"])),
    ("trusted-types none", with_directive("trusted-types", ["'none'"])),
    ("require-trusted-types-for style", with_directive("require-trusted-types-for", ["'script'", "'style'"])),
    ("base-uri self", with_directive("base-uri", ["'self'"])),
    ("form-action self", with_directive("form-action", ["'self'"])),
    ("frame-ancestors self", with_directive("frame-ancestors", ["'self'"])),
    ("empty value", ""),
)

LEAD = "<!doctype html><html><head><title>t</title></head><body>"
TAIL = "</body></html>"


def page(body, head=""):
    return "<!doctype html><html><head><title>t</title>%s</head><body>%s</body></html>" % (head, body)


# (row name, page html). Each must produce at least one refusal under the shipped policy.
REFUSE_PAGES = (
    ("inline script", page("<script>window.q=1</script>")),
    ("script without src and without body", page("<script></script>")),
    ("data-src is not src", page('<script data-src="/index.js"></script>')),
    ("script src with an inline body", page('<script src="/index.js">window.q=1</script>')),
    ("script src from a foreign host", page('<script src="https://cdn.example.com/x.js"></script>')),
    ("script type module inline", page('<script type="module">import("/x.js")</script>')),
    ("onclick handler", page('<button onclick="q()">x</button>')),
    ("mixed case handler", page('<button OnClick="q()">x</button>')),
    ("img onerror", page('<img src="data:image/png;base64,AAAA" onerror="q()">')),
    ("body onload", page("", head="").replace("<body>", '<body onload="q()">')),
    ("javascript: href", page('<a href="javascript:q()">x</a>')),
    ("javascript: href with spaces and case", page('<a href="  JaVa\n\tScRiPt:q()">x</a>')),
    ("javascript: href with a numeric entity", page('<a href="&#106;avascript:q()">x</a>')),
    ("javascript: href with a hex entity and a tab", page('<a href="java&#x09;script:q()">x</a>')),
    ("javascript: href double encoded", page('<a href="&amp;#106;avascript:q()">x</a>')),
    ("javascript: href with zero-width space", page('<a href="java\u200bscript:q()">x</a>')),
    ("vbscript: href", page('<a href="vbscript:q()">x</a>')),
    ("javascript: form action", page('<a formaction="javascript:q()">x</a>')),
    ("base href", page("", head='<base href="https://evil.example/">')),
    ("base target", page("", head='<base target="_blank">')),
    ("svg script href", page('<svg><script href="data:text/javascript,q()"></script></svg>')),
    ("svg script xlink:href", page('<svg><script xlink:href="data:text/javascript,q()"></script></svg>')),
    ("svg anchor xlink:href javascript:", page('<svg><a xlink:href="javascript:q()"><text>x</text></a></svg>')),
    ("svg use", page('<svg><use href="https://evil.example/a.svg#x"></use></svg>')),
    ("svg image", page('<svg><image href="https://evil.example/a.png"></image></svg>')),
    ("svg foreignObject", page("<svg><foreignObject><div>x</div></foreignObject></svg>")),
    ("svg with an inline handler", page('<svg onload="q()"></svg>')),
    ("style block with an escaped url", page("", head="<style>a{background:url(\\68ttps://evil.example/x.png)}</style>")),
    ("style attribute with an escaped url", page('<div style="background:url(\\68ttps://evil.example/x.png)">x</div>')),
    ("style block with an escaped import", page("", head="<style>@import \\75rl(https://evil.example/a.css);</style>")),
    ("stylesheet from a foreign host", page("", head='<link rel="stylesheet" href="https://evil.example/a.css">')),
    ("stylesheet via protocol-relative url", page("", head='<link rel="stylesheet" href="//evil.example/a.css">')),
    ("img from a foreign host", page('<img src="https://evil.example/x.png">')),
    ("img srcset with a data comma", page('<img srcset="data:image/png;base64,AAAA 1x, https://evil.example/x.png 2x">')),
    ("img srcset alone", page('<img srcset="/a.png 1x">')),
    ("link imagesrcset", page("", head='<link rel="preload" as="image" imagesrcset="/a.png 1x">')),
    ("body meta CSP", page('<meta http-equiv="Content-Security-Policy" content="img-src *">')),
    ("head meta CSP", page("", head='<meta http-equiv="content-security-policy" content="default-src *">')),
    ("meta refresh", page("", head='<meta http-equiv="refresh" content="0;url=https://evil.example/">')),
    ("iframe", page('<iframe src="/x.html"></iframe>')),
    ("object", page('<object data="/x.swf"></object>')),
    ("embed", page('<embed src="/x.swf">')),
    ("form", page('<form action="/x"><input></form>')),
    ("font from a foreign host via link preload", page("", head='<link rel="preload" as="font" href="https://evil.example/f.woff2">')),
    ("manifest link", page("", head='<link rel="manifest" href="/m.json">')),
)


class RefuseTable7636(unittest.TestCase):
    def test_every_policy_row_is_refused(self):
        accepted = [name for name, policy in REFUSE_POLICIES if not csp.check_policy(policy)]
        self.assertEqual(accepted, [])

    def test_every_page_row_is_refused_under_the_shipped_policy(self):
        accepted = [name for name, html in REFUSE_PAGES if not csp.check_page(html, shipped())]
        self.assertEqual(accepted, [])

    def test_the_review_rows_are_all_present(self):
        names = [n for n, _ in REFUSE_POLICIES] + [n for n, _ in REFUSE_PAGES]
        for number in ("7636", "7637", "7638"):
            self.assertTrue([n for n in names if n.startswith(number)], number)

    def test_every_refusal_names_the_file_to_edit_and_the_doc_section(self):
        for name, policy in REFUSE_POLICIES:
            for refusal in csp.check_policy(policy):
                self.assertIn("cf_csp_allowlist_7313.py", refusal, name)
                self.assertIn("Widening the CSP allowlist", refusal, name)
        for name, html in REFUSE_PAGES:
            for refusal in csp.check_page(html, shipped()):
                self.assertIn("cf_csp_allowlist_7313.py", refusal, name)
                self.assertIn("Widening the CSP allowlist", refusal, name)

    def test_a_refusal_names_the_directive_and_the_token(self):
        refusals = csp.check_policy(with_directive("script-src", ["'self'", "'unsafe-eval'"]))
        self.assertTrue(any("script-src" in r and "'unsafe-eval'" in r for r in refusals), refusals)
        refusals = csp.check_policy(appended("worker-src 'self'"))
        self.assertTrue(any("worker-src" in r for r in refusals), refusals)

    def test_a_path_with_no_policy_or_two_policies_is_refused(self):
        refusals, value = csp.check_path("/other\n  X-Frame-Options: DENY\n", "/index.html")
        self.assertTrue(refusals and value is None, refusals)
        two = "/*\n  Content-Security-Policy: %s\n/*.html\n  Content-Security-Policy: %s\n" % (shipped(), shipped())
        refusals, value = csp.check_path(two, "/index.html")
        self.assertTrue(any("exactly one" in r and "line 4" in r for r in refusals), refusals)
        self.assertIsNone(value)

    def test_a_wildcard_and_an_own_host_source_are_refused_even_when_safe(self):
        """The documented false refusal: the table has no wildcard and no own-host entry."""
        for token in ("*", "https://dash.example"):
            self.assertTrue(csp.check_policy(with_directive("connect-src", ["'self'", token])), token)

    def test_unsafe_inline_has_no_exception_anywhere_7689(self):
        self.assertEqual(dict(csp.DOCUMENTED_EXCEPTIONS), {})
        for name, tokens in csp.ALLOWED_DIRECTIVES.items():
            self.assertNotIn("'unsafe-inline'", tokens, name)
        self.assertTrue(csp.check_policy(with_directive("style-src", ["'self'", "'unsafe-inline'"])))
        self.assertNotIn("'unsafe-inline'", shipped())

    def test_inline_style_is_always_refused_7689(self):
        """A style attribute and a <style> block are refused whatever the policy says: there is no exception left."""
        tight = with_directive("style-src", ["'self'", "https://fonts.googleapis.com"])
        self.assertEqual(csp.check_policy(tight), [])
        for html in (page('<div style="color:red">x</div>'), page("<p>x</p>", head="<style>a{color:red}</style>"),
                     page('<svg><text style="fill:red"></text></svg>')):
            self.assertTrue(csp.check_page(html, tight), html)
            self.assertTrue(csp.check_page(html, shipped()), html)

    def test_the_real_pages_have_no_inline_style_and_load_a_local_stylesheet_7689(self):
        for path in sorted(PUBLIC.glob("*.html")):
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("<style", text, path.name)
            self.assertNotIn(" style=", text, path.name)
            self.assertIn('rel="stylesheet" href="/', text, path.name)

    def test_a_policy_missing_a_directive_a_load_needs_is_refused(self):
        weak = with_directive("img-src", ["'self'"])
        html = page('<img src="data:image/png;base64,AAAA">')
        self.assertTrue(any("img-src" in r and "data:" in r for r in csp.check_page(html, weak)))


def policy_file(*rules):
    """A `_headers` text from (pattern, [header lines]) pairs."""
    return "".join("%s\n%s" % (pattern, "".join("  %s\n" % h for h in headers)) for pattern, headers in rules)


class HeadersFailClosed7685(unittest.TestCase):
    """#7685 #7686: the `_headers` reader refuses what it cannot prove it understands, with the line number, in the checker
    and in the browser test server alike."""

    CSP = None

    @classmethod
    def setUpClass(cls):
        cls.CSP = "Content-Security-Policy: " + shipped()

    def refused(self, text, line, needle, path="/index.html"):
        refusals, value = csp.check_path(text, path)
        self.assertIsNone(value, text)
        self.assertTrue(any(("line %d" % line) in r and needle in r for r in refusals), (line, needle, refusals))

    def test_a_csp_stripped_with_a_removal_line_is_refused(self):
        for removal in ("! Content-Security-Policy", "!Content-Security-Policy", "\t! content-security-policy"):
            text = policy_file(("/*", [self.CSP]), ("/index.html", [removal.strip()]))
            self.refused(text, 4, "!")
        self.refused(policy_file(("/*", [self.CSP, "! X-Frame-Options"])), 3, "!")

    def test_a_rule_whose_pattern_is_not_a_plain_path_is_refused(self):
        for pattern in ("https://dash.example/*", "https://*.example.com/*", "*.example.com/*", "//dash.example/*",
                        "http://:sub.example.com/*", "dash.example/*", "https://:project.pages.dev/*"):
            text = policy_file((pattern, [self.CSP]), ("/*", [self.CSP]))
            self.refused(text, 1, pattern)

    def test_a_non_ascii_byte_anywhere_in_the_file_is_refused(self):
        for bad in ("\u00a0", "\u2003", "\u3000", "\u0085", "\u200b", "\ufeff", "\u00e9"):
            text = policy_file(("/*", [self.CSP.replace("script-src 'self'", "script-src" + bad + "'self'")]))
            self.refused(text, 2, "non-ASCII")
        self.refused("/*\n  X-Test: a\u00e9\n  " + self.CSP + "\n", 2, "non-ASCII")

    def test_a_no_break_space_inside_a_csp_directive_is_not_a_separator(self):
        for bad in ("\u00a0", "\u2003", "\u3000", "\u0085", "\x0b", "\x1f"):
            policy = shipped().replace("script-src 'self'", "script-src" + bad + "'self'")
            self.assertTrue(csp.check_policy(policy), repr(bad))
        for good in ("\t", "\n", "\f", "\r", "  "):
            self.assertEqual(csp.check_policy(shipped().replace("script-src 'self'", "script-src" + good + "'self'")), [])

    def test_a_second_csp_header_is_refused_with_its_line(self):
        same_block = policy_file(("/*", [self.CSP, self.CSP]))
        self.refused(same_block, 3, "exactly one")
        two_rules = policy_file(("/*", [self.CSP]), ("/*.json", [self.CSP]))
        self.refused(two_rules, 4, "exactly one", "/state.json")

    def test_a_malformed_file_is_refused_not_skipped(self):
        self.refused("  X-Frame-Options: DENY\n/*\n  " + self.CSP + "\n", 1, "before any rule")
        self.refused("/*\n  X-Frame-Options\n  " + self.CSP + "\n", 2, "name: value")
        self.refused("/*\n  # note\n  " + self.CSP + "\n", 2, "comment")
        self.refused("/*\n  Bad Name: x\n  " + self.CSP + "\n", 2, "header name")

    def test_the_browser_test_server_reads_headers_through_the_same_refusals(self):
        for text in (policy_file(("/*", [self.CSP]), ("/index.html", ["! Content-Security-Policy"])),
                     policy_file(("https://dash.example/*", [self.CSP])),
                     policy_file(("/*", [self.CSP.replace("script-src", "script-src\u00a0")]))):
            with self.assertRaises(ValueError):
                cdp.headers_for(text, "/")

    def test_the_shipped_headers_parse_and_are_the_only_policy(self):
        pairs = cdp.headers_for(HEADERS, "/")
        self.assertEqual([n for n, _ in pairs].count("Content-Security-Policy"), 1)


class AcceptShipped7636(unittest.TestCase):
    def test_the_shipped_headers_are_accepted_for_every_served_path(self):
        paths = ["/", "/state.json", "/mcp-tools-state.json"]
        for page_file in sorted(PUBLIC.glob("*.html")):
            paths.extend(origin_mod.served_paths(page_file.name))
        for path in paths:
            refusals, value = csp.check_path(HEADERS, path)
            self.assertEqual(refusals, [], path)
            self.assertIsNotNone(value)

    def test_the_whole_site_is_accepted(self):
        self.assertEqual(csp.check_site(PUBLIC), [])

    def test_the_shipped_policy_carries_the_trusted_types_pair(self):
        tokens = csp.policy_tokens(shipped())
        self.assertEqual(tokens["require-trusted-types-for"], {"'script'"})
        self.assertEqual(tokens["trusted-types"], {"dash"})
        self.assertNotIn("'unsafe-inline'", tokens["script-src"])
        self.assertNotIn("'unsafe-eval'", tokens["script-src"])

    def test_a_static_empty_svg_container_and_a_data_icon_are_accepted(self):
        html = page('<svg id="ringsvg" width="94" height="94"></svg>',
                    head="<link rel=\"icon\" href=\"data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg'></svg>\">")
        self.assertEqual(csp.check_page(html, shipped()), [])

    def test_an_external_script_with_src_and_data_src_attributes_is_accepted_only_when_src_is_local(self):
        self.assertEqual(csp.check_page(page('<script src="/index.js" defer data-src="x"></script>'), shipped()), [])

    def test_frame_and_cache_headers_stay_as_shipped(self):
        self.assertIn("frame-ancestors 'none'", shipped())
        self.assertIn("X-Frame-Options: DENY", HEADERS)
        self.assertEqual(HEADERS.count("/state.json"), 0, "redundant /state.json rule (covered by /*.json)")

    def test_the_emulation_is_gone(self):
        for name in ("CHAINS", "parse_policy", "csp_sources", "source_allows", "effective_directive", "load_allowed",
                     "blocked_loads", "policies_of", "derived_loads", "Source", "Policy", "_classify"):
            self.assertFalse(hasattr(origin_mod, name), name)


if __name__ == "__main__":
    unittest.main()
