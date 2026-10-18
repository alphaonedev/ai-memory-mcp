"""#7594: after a fetch or render error each of the six V&V sub-pages keeps its last good data, shows an error banner
with a Retry button, and never sits on a permanent "loading" message. Run in headless Chromium with the real CSP."""
import copy
import json
import unittest

import cf_pages_harness_7313 as harness

PAGES = ("datatier", "federation", "mcp-tools", "northstar", "security", "swarm-tools")
GOOD_CARD = ".fam"
BANNER = "[role=alert]"
RETRY = "[role=alert] button"
REFRESH_BUDGET_MS = 10 * 60 * 1000  # the pages poll far more often than this


def good_state(name):
    return json.loads((harness.PUBLIC / (name + "-state.json")).read_text(encoding="utf-8"))


class SubPageResilience7594(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        harness.playwright_or_skip(cls, unittest)

    @classmethod
    def tearDownClass(cls):
        harness.stop(cls)

    def open(self, name, clock=False):
        site = harness.Site(self._browser, install_clock=clock)
        self.addCleanup(site.close)
        return site

    def cards(self, site):
        return site.page.locator(GOOD_CARD).count()

    def test_a_normal_load_renders_every_family_under_the_real_csp(self):
        for name in PAGES:
            with self.subTest(page=name):
                site = self.open(name)
                site.goto("/" + name)
                site.settle()
                self.assertEqual(self.cards(site), len(good_state(name)["groups"]))
                self.assertEqual(site.errors, [])
                self.assertEqual(site.violations(), [])
                self.assertEqual(site.page.locator(BANNER).count(), 0)

    def test_a_failed_first_load_shows_an_error_with_retry_not_a_permanent_loading_message(self):
        for name in PAGES:
            with self.subTest(page=name):
                site = self.open(name)
                site.answer["/%s-state.json" % name] = (500, "boom")
                site.goto("/" + name)
                site.settle()
                self.assertEqual(site.page.locator(BANNER).count(), 1)
                self.assertEqual(site.page.locator(RETRY).count(), 1)
                self.assertNotIn("loading validation data", site.page.inner_text("body"))
                del site.answer["/%s-state.json" % name]
                site.page.click(RETRY)
                site.settle()
                self.assertEqual(self.cards(site), len(good_state(name)["groups"]))
                self.assertEqual(site.page.locator(BANNER).count(), 0)

    def test_a_failed_refresh_keeps_the_last_good_data_and_offers_retry(self):
        for name in PAGES:
            with self.subTest(page=name):
                site = self.open(name, clock=True)
                site.goto("/" + name)
                site.settle()
                before = site.page.inner_text("#families")
                self.assertTrue(before.strip())
                site.answer["/%s-state.json" % name] = (503, "down")
                site.page.clock.run_for(REFRESH_BUDGET_MS)
                site.settle()
                self.assertEqual(site.page.inner_text("#families"), before, "last good data was dropped")
                self.assertEqual(site.page.locator(BANNER).count(), 1)
                self.assertNotIn("loading validation data", site.page.inner_text("body"))
                del site.answer["/%s-state.json" % name]
                site.page.click(RETRY)
                site.settle()
                self.assertEqual(site.page.locator(BANNER).count(), 0)
                self.assertEqual(site.page.inner_text("#families"), before)

    def test_a_state_that_cannot_render_keeps_the_last_good_data(self):
        for name in PAGES:
            with self.subTest(page=name):
                site = self.open(name, clock=True)
                site.goto("/" + name)
                site.settle()
                before = site.page.inner_text("#families")
                broken = copy.deepcopy(good_state(name))
                broken["groups"][0]["tools"] = "not-a-list"
                site.answer["/%s-state.json" % name] = (200, json.dumps(broken))
                site.page.clock.run_for(REFRESH_BUDGET_MS)
                site.settle()
                self.assertEqual(site.page.inner_text("#families"), before, "a render error replaced the last good data")
                self.assertEqual(site.page.locator(BANNER).count(), 1)

    def test_an_unparsable_json_body_is_an_error_state_too(self):
        for name in PAGES:
            with self.subTest(page=name):
                site = self.open(name)
                site.answer["/%s-state.json" % name] = (200, "<html>not json")
                site.goto("/" + name)
                site.settle()
                self.assertEqual(site.page.locator(BANNER).count(), 1)
                self.assertNotIn("loading validation data", site.page.inner_text("body"))

    def test_an_invalid_last_updated_date_does_not_break_the_render(self):
        for name in PAGES:
            with self.subTest(page=name):
                site = self.open(name)
                bad = copy.deepcopy(good_state(name))
                bad["lastUpdated"] = "not a date"
                site.answer["/%s-state.json" % name] = (200, json.dumps(bad))
                site.goto("/" + name)
                site.settle()
                self.assertEqual(self.cards(site), len(good_state(name)["groups"]))
                self.assertEqual(site.page.locator(BANNER).count(), 0)
                self.assertEqual(site.errors, [])

    def test_the_total_in_the_subtitle_of_the_two_tool_pages_is_kept(self):
        for name in ("mcp-tools", "swarm-tools"):
            with self.subTest(page=name):
                site = self.open(name)
                site.goto("/" + name)
                site.settle()
                self.assertIn("%s tools exercised" % good_state(name)["total"], site.page.inner_text("#sub"))


if __name__ == "__main__":
    unittest.main()
