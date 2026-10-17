"""`_headers` rule collection for the CSP checks (#7589 #7590 #7591).

The earlier coverage table here compared an emulation of a browser's CSP matching with headless Chromium. The
emulation is gone (#7636-#7638): the checker is an allowlist that fails closed (cf_csp_allowlist_7313.py,
test_cf_csp_allowlist_7636.py). What stays is how `_headers` rules are collected for a served path.
"""
import unittest

import cf_origin_7313 as origin_mod


class HeaderRules7589(unittest.TestCase):
    HEADERS = ("/*\n  Content-Security-Policy: img-src 'self'\n  X-Frame-Options: DENY\n"
               "/*.html\n  Content-Security-Policy: script-src 'none', style-src 'none'\n"
               "/*.json\n  Content-Security-Policy: default-src 'none'\n")

    def test_header_policies_collects_every_matching_rule_and_splits_commas(self):
        self.assertEqual(origin_mod.header_policies(self.HEADERS, "/page.html"),
                         ["img-src 'self'", "script-src 'none'", "style-src 'none'"])
        self.assertEqual(origin_mod.header_policies(self.HEADERS, "/state.json"),
                         ["img-src 'self'", "default-src 'none'"])
        self.assertEqual(origin_mod.header_policies(self.HEADERS, "/"), ["img-src 'self'"])


if __name__ == "__main__":
    unittest.main()
