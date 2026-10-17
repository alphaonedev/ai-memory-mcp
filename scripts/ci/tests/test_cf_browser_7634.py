"""#7634 #7639: the dashboard in a real Chrome / Chromium, driven with the standard library only (cf_cdp_7313.py).

What the page does in a browser is the claim, so the browser decides it: the served response carries the Trusted Types
directives, a normal and a hostile state render with 0 Trusted Types violations, 0 CSP violations, an empty console
and every panel populated, nothing hostile executes, and every string-to-HTML sink a page script could try is refused
by the browser. Two mutation tests prove the test turns red: an injected `el.innerHTML = s`, and a `_headers` without
`require-trusted-types-for`. A last test loads the page in a browser WITHOUT Trusted Types (no header directives, no
window.trustedTypes): it still renders, through the escaping `markup` tag and `script-src 'self'`.

A missing browser SKIPS the class, except where CF_DASH_REQUIRE_BROWSER=1 (the CI step), where it FAILS.
"""
import copy
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

import cf_cdp_7313 as cdp
import cf_csp_allowlist_7313 as csp
import cf_xss_guard_7587 as guard

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "index_state_7587.json"
HEADERS_TEXT = (cdp.PUBLIC / "_headers").read_text(encoding="utf-8")
REQUIRE_ENV = "CF_DASH_REQUIRE_BROWSER"
TT_DIRECTIVES = ("require-trusted-types-for 'script'", "trusted-types dash")
INFINITY_MARK = "\u0000INF"
PAYLOAD = '"><i class="pwn7634" onclick="window.__pwn=1">x</i><img src=x onerror="window.__pwn=2"><svg onload="window.__pwn=3">'
JS_PAYLOAD = "javascript:window.__pwn=4"

# panel selector -> number of elements the normal fixture state renders (#7639: a blank panel is a failure)
PANELS = {
    "#livebadge > *": 2, "#ringsvg > *": 3, "#kpis > *": 5, "#pillars > *": 4, "#hwmon > *": 2, "#domon > *": 3,
    "#swarmwrap > *": 4, "#swarm > *": 1, "#tpchart > *": 1, "#fedchart > *": 1, "#a2apanel > *": 3,
    "#bootpanel > *": 1, "#oplatpanel > *": 1, "#commspanel > *": 1, "#capchart > *": 1, "#wpchart > *": 1,
    "#aiusage > *": 3, "#latchart > *": 1, "#covchart > *": 1, "#scalechart > *": 1, "#secpanel > *": 1,
    "#cycpanel > *": 2, "#campaignsPanel > *": 4, "#board > *": 4, "#issuespanel > *": 1, "#feed > *": 1,
    "#agentsPanel > *": 2, "#cfgpre > *": 6,
}
SELECTORS = list(PANELS)

SHAPES_JS = """
window.__shapes = {};
(function(){
  const t = (name, fn) => { try { fn(); window.__shapes[name] = "ran"; } catch (e) { window.__shapes[name] = "threw " + e.name; } };
  const s = "<img src=x onerror=window.__pwn=7>";
  const host = document.createElement("div"); document.body.appendChild(host);
  t("innerHTML", () => { host.innerHTML = s; });
  t("computed innerHTML", () => { host["inner" + "HTML"] = s; });
  t("outerHTML", () => { const d = document.createElement("div"); host.appendChild(d); d.outerHTML = s; });
  t("insertAdjacentHTML", () => { host.insertAdjacentHTML("beforeend", s); });
  t("createContextualFragment", () => { document.createRange().createContextualFragment(s); });
  t("DOMParser", () => { new DOMParser().parseFromString(s, "text/html"); });
  if ("setHTMLUnsafe" in host) { t("setHTMLUnsafe", () => { host.setHTMLUnsafe(s); }); }
  t("srcdoc", () => { const f = document.createElement("iframe"); f.srcdoc = s; });
  t("eval", () => { eval("window.__pwn = 8"); });
  t("Function", () => { new Function("window.__pwn = 9")(); });
  t("setTimeout string", () => { setTimeout("window.__pwn = 10", 0); });
  t("script text", () => { const sc = document.createElement("script"); sc.text = "window.__pwn = 11"; });
  t("script src", () => { const sc = document.createElement("script"); sc.src = "/probe.js"; });
  t("second dash policy", () => { window.trustedTypes.createPolicy("dash", {}); });
  t("other policy", () => { window.trustedTypes.createPolicy("other", {}); });
  t("markup called as a function", () => { markup("<b>x</b>"); });
  t("put a string", () => { put(host, "<b>x</b>"); });
})();
"""
CHEAT_SHAPES = ("markup called as a function", "put a string")  # refused by index.js itself, with or without Trusted Types
NO_TT_SHAPES = {"innerHTML", "computed innerHTML", "outerHTML", "insertAdjacentHTML", "createContextualFragment",
                "DOMParser", "srcdoc", "setHTMLUnsafe", "script text", "script src"}


def leaves(value, fn, path=()):
    if isinstance(value, dict):
        out = {k: leaves(v, fn, path + (k,)) for k, v in value.items()}
        out["createHTML"] = PAYLOAD
        out["__proto__"] = {"polluted": PAYLOAD, "createHTML": PAYLOAD}
        out["toString"] = PAYLOAD
        return out
    if isinstance(value, list):
        return [leaves(v, fn, path + (str(i),)) for i, v in enumerate(value)]
    if isinstance(value, bool) or value is None:
        return value
    return fn(value, path)


def hostile_text(base):
    """The hostile state as JSON text: every string is markup or a javascript: URL, every number is 1e999."""
    def leaf(value, path):
        if isinstance(value, (int, float)):
            return INFINITY_MARK
        return (PAYLOAD + value) if len(path) % 2 else (JS_PAYLOAD if "url" in "/".join(path).lower() else PAYLOAD)
    state = leaves(base, leaf)
    state["run_active"] = True
    return json.dumps(state).replace('"\\u0000INF"', "1e999")


def without(headers_text, directives):
    out = headers_text
    for directive in directives:
        out = out.replace("; " + directive, "")
    return out


class BrowserCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = cdp.find_browser()
        if cls.binary is None:
            if os.environ.get(REQUIRE_ENV) == "1":
                raise AssertionError("%s=1 and no Chrome or Chromium was found (set CF_DASH_CHROME or install one)" % REQUIRE_ENV)
            raise unittest.SkipTest("no Chrome or Chromium (set CF_DASH_CHROME); %s=1 makes this a failure" % REQUIRE_ENV)
        version = subprocess.run([cls.binary, "--version"], capture_output=True, text=True, timeout=60).stdout.strip()
        sys.stderr.write("cf-dashboard browser test: running against %s (%s)\n" % (version, cls.binary))
        cls.state = FIXTURE.read_text(encoding="utf-8")
        cls.state_json = json.loads(cls.state)

    def run_page(self, state_text=None, headers_text=None, **kwargs):
        browser = cdp.Browser(self.binary)
        self.addCleanup(browser.close)
        return cdp.load(browser, HEADERS_TEXT if headers_text is None else headers_text,
                        self.state if state_text is None else state_text, SELECTORS, **kwargs)


def assert_tt_header(result):
    """The served response for `/` carries the Trusted Types directives, and the browser saw the same."""
    served = dict(next(headers for path, headers in result["served"] if path == "/"))
    for directive in TT_DIRECTIVES:
        assert directive in served.get("Content-Security-Policy", ""), "the served / has no `%s`" % directive
        assert directive in (result["csp"] or ""), "the browser fetched / without `%s`" % directive


def assert_clean(result, counts=None, strict_log=True):
    """0 Trusted Types violations, 0 CSP violations, empty console, no exception, nothing executed, panels rendered."""
    assert result["v"] == [], "violations: %s" % result["v"]
    assert result["exceptions"] == [], "exceptions: %s" % result["exceptions"]
    if strict_log:
        assert result["console"] == [], "console: %s" % result["console"]
        assert result["log"] == [], "log: %s" % result["log"]
    else:  # 1e999 makes SVG attributes NaN: Chrome logs a rendering error per attribute, which is data validity, not safety
        stray = [m for m in result["log"] if not m.startswith("rendering/error:")]
        assert stray == [], "log: %s" % stray
    assert result["pwn"] == "undefined", "window.__pwn is %s" % result["pwn"]
    if counts is not None:
        for selector, expected in counts.items():
            got = result["counts"][selector]
            assert (got > 0) if expected == "any" else (got == expected),"%s rendered %s, expected %s" % (selector, got, expected)


class DashboardInChrome7634(BrowserCase):
    def test_the_served_response_carries_the_trusted_types_directives(self):
        result = self.run_page()
        assert_tt_header(result)
        self.assertEqual(result["tt"], "object", "this browser must support Trusted Types")

    def test_a_normal_state_renders_every_panel_with_no_violation_and_an_empty_console(self):
        result = self.run_page()
        assert_clean(result, PANELS)
        self.assertFalse(result["live"].startswith("offline"), result["live"])

    def test_a_hostile_state_in_every_panel_is_inert_and_still_renders(self):
        text = hostile_text(self.state_json)
        self.assertIn("1e999", text)
        self.assertIn('"__proto__"', text)
        self.assertIn('"createHTML"', text)
        self.assertIn("javascript:window.__pwn=4", text)
        result = self.run_page(state_text=text)
        assert_clean(result, {selector: "any" for selector in PANELS}, strict_log=False)
        self.assertEqual(result["pwn"], "undefined")

    def test_every_string_to_html_sink_a_page_script_could_try_is_refused_by_the_browser(self):
        result = self.run_page(js_append=SHAPES_JS)
        shapes = result["shapes"]
        self.assertGreaterEqual(len(shapes), 16, shapes)
        self.assertEqual({name: how for name, how in shapes.items() if not how.startswith("threw")}, {})
        self.assertEqual(result["pwn"], "undefined")
        violations = [v["eff"] for v in result["v"]]
        self.assertIn("require-trusted-types-for", violations)
        self.assertIn("trusted-types", violations, "the duplicate/other policy must be refused by trusted-types dash")

    def test_the_page_script_exposes_no_policy_or_html_class(self):
        result = self.run_page(js_append="window.__shapes = {dash: typeof dash, html: typeof Html, esc: typeof escText,"
                                         " win: typeof window.markup, pol: typeof window.dash, tt: String(window.trustedTypes"
                                         ".defaultPolicy)};")
        self.assertEqual(result["shapes"], {"dash": "undefined", "html": "undefined", "esc": "undefined",
                                            "win": "undefined", "pol": "undefined", "tt": "null"})


class MutationProofs7634(BrowserCase):
    """The test above is only worth anything if it goes red when the protection is gone."""

    INJECT = '{ const el = document.getElementById("kpis"); const s = "<b>injected</b>"; el.innerHTML = s; }'

    def test_an_injected_innerhtml_assignment_turns_the_browser_test_red(self):
        result = self.run_page(js_append=self.INJECT)
        self.assertTrue([v for v in result["v"] if v["eff"] == "require-trusted-types-for"], result["v"])
        with self.assertRaises(AssertionError):
            assert_clean(result, PANELS)

    def test_an_injected_innerhtml_assignment_also_turns_the_static_guard_red(self):
        src = (cdp.PUBLIC / "index.js").read_text(encoding="utf-8") + "\n" + self.INJECT
        self.assertTrue(guard.js_problems(src, True))

    def test_a_headers_file_without_require_trusted_types_for_turns_it_red(self):
        weak = without(HEADERS_TEXT, ("require-trusted-types-for 'script'",))
        self.assertNotIn("require-trusted-types-for", weak)
        result = self.run_page(headers_text=weak, js_append=self.INJECT)
        with self.assertRaises(AssertionError):
            assert_tt_header(result)
        # and the browser really does stop enforcing: the injected markup lands in the DOM unchallenged
        self.assertEqual(result["v"], [])
        self.assertTrue(csp.check_policy(weak.split("Content-Security-Policy:")[1].split("\n")[0].strip()))

    def test_without_trusted_types_enforcement_the_sinks_run(self):
        weak = without(HEADERS_TEXT, TT_DIRECTIVES)
        result = self.run_page(headers_text=weak, js_append=SHAPES_JS.replace("document.write(s);", ""))
        ran = {name for name, how in result["shapes"].items() if how == "ran"}
        self.assertTrue({"innerHTML", "computed innerHTML", "insertAdjacentHTML"} <= ran, result["shapes"])
        for name in CHEAT_SHAPES:
            self.assertTrue(result["shapes"][name].startswith("threw"), (name, result["shapes"]))


class NoTrustedTypes7634(BrowserCase):
    """A browser without Trusted Types (Firefox, Safari): no directives, no window.trustedTypes."""

    HIDE = "Object.defineProperty(window, 'trustedTypes', {value: undefined, configurable: true});"

    def test_the_page_renders_through_the_escaping_fallback(self):
        weak = without(HEADERS_TEXT, TT_DIRECTIVES)
        result = self.run_page(headers_text=weak, init_script=self.HIDE)
        self.assertEqual(result["tt"], "undefined")
        assert_clean(result, PANELS)

    def test_a_hostile_state_is_inert_without_trusted_types_too(self):
        weak = without(HEADERS_TEXT, TT_DIRECTIVES)
        result = self.run_page(state_text=hostile_text(self.state_json), headers_text=weak, init_script=self.HIDE)
        self.assertEqual(result["tt"], "undefined")
        assert_clean(result, {selector: "any" for selector in PANELS}, strict_log=False)


class RequireBrowser7639(unittest.TestCase):
    def test_a_missing_browser_fails_when_the_ci_switch_is_set(self):
        saved = {k: os.environ.get(k) for k in (REQUIRE_ENV, cdp.BROWSER_ENV, "PATH")}
        try:
            os.environ[REQUIRE_ENV] = "1"
            os.environ[cdp.BROWSER_ENV] = "/nonexistent/chrome"
            with self.assertRaises(AssertionError):
                BrowserCase.setUpClass.__func__(BrowserCase)
            os.environ[REQUIRE_ENV] = "0"
            with self.assertRaises(unittest.SkipTest):
                BrowserCase.setUpClass.__func__(BrowserCase)
        finally:
            for key, value in saved.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value


if __name__ == "__main__":
    unittest.main()
