"""`_headers` rule collection for the CSP checks (#7589 #7590 #7591, #7685).

The earlier coverage table here compared an emulation of a browser's CSP matching with headless Chromium. The
emulation is gone (#7636-#7638): the checker is an allowlist that fails closed (cf_csp_allowlist_7313.py,
test_cf_csp_allowlist_7636.py). What stays is how `_headers` rules are collected for a served path, by the one shared
reader (cf_headers_7313.py); its refusals are in test_cf_csp_allowlist_7636.py (HeadersFailClosed7685).
"""
import unittest

import cf_headers_7313 as headers_mod


class HeaderRules7589(unittest.TestCase):
    HEADERS = ("/*\n  Content-Security-Policy: script-src 'none', style-src 'none'\n  X-Frame-Options: DENY\n"
               "/*.html\n  Cache-Control: no-store\n"
               "/*.json\n  Cache-Control: max-age=0\n")

    def test_headers_for_collects_every_matching_rule_in_file_order(self):
        self.assertEqual([n for n, _ in headers_mod.headers_for(self.HEADERS, "/page.html")],
                         ["Content-Security-Policy", "X-Frame-Options", "Cache-Control"])
        self.assertEqual(headers_mod.headers_for(self.HEADERS, "/state.json")[-1], ("Cache-Control", "max-age=0"))
        self.assertEqual([n for n, _ in headers_mod.headers_for(self.HEADERS, "/")],
                         ["Content-Security-Policy", "X-Frame-Options"])

    def test_csp_policies_split_a_header_value_on_commas(self):
        self.assertEqual(headers_mod.csp_policies(self.HEADERS, "/page.html"), ["script-src 'none'", "style-src 'none'"])
        self.assertEqual(headers_mod.csp_values(self.HEADERS, "/")[0], "script-src 'none', style-src 'none'")

    def test_a_pattern_is_a_splat_or_a_one_segment_placeholder(self):
        rx = headers_mod.pattern_regex("/docs/:name/*.html")
        self.assertTrue(rx.match("/docs/a/b.html"))
        self.assertFalse(rx.match("/docs/a/b.json"))
        self.assertFalse(rx.match("/docs//b.html"))


if __name__ == "__main__":
    unittest.main()
