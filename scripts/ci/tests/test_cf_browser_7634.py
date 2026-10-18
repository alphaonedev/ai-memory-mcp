"""#7634 #7639: the dashboard in a real Chrome / Chromium, driven with the standard library only (cf_cdp_7313.py).

What the page does in a browser is the claim, so the browser decides it: the served response carries the Trusted Types
directives, a normal and a hostile state render with 0 Trusted Types violations, 0 CSP violations, an empty console
and every panel populated, nothing hostile executes, and every string-to-HTML sink a page script could try is refused
by the browser. Two mutation tests prove the test turns red: an injected `el.innerHTML = s`, and a `_headers` without
`require-trusted-types-for`. A last test loads the page in a browser WITHOUT Trusted Types (no header directives, no
window.trustedTypes): it still renders, through the escaping `markup` tag and `script-src 'self'`.

A missing browser SKIPS the class, except where CF_DASH_REQUIRE_BROWSER=1 (the CI step), where it FAILS.
"""
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
# the hostile state (every string markup, every number 1e999): a value that is not a finite number is omitted from SVG
# and shown as the text placeholder elsewhere, so the same panels render and nothing is logged (#7687 #7688). Pinned,
# not "any". Two panels differ from the normal counts, for stated reasons: the ring keeps only its base circle (its
# two data arcs have non-finite geometry and are omitted), and the A2A panel gains four bars (the hostile keys
# createHTML, __proto__, toString and constructor are four extra own entries of `types`, each rendered as plain text).
HOSTILE_PANELS = {
    "#livebadge > *": 2, "#ringsvg > *": 1, "#kpis > *": 5, "#pillars > *": 4, "#hwmon > *": 2, "#domon > *": 3,
    "#swarmwrap > *": 4, "#swarm > *": 1, "#tpchart > *": 1, "#fedchart > *": 1, "#a2apanel > *": 7,
    "#bootpanel > *": 1, "#oplatpanel > *": 1, "#commspanel > *": 1, "#capchart > *": 1, "#wpchart > *": 1,
    "#aiusage > *": 3, "#latchart > *": 1, "#covchart > *": 1, "#scalechart > *": 1, "#secpanel > *": 1,
    "#cycpanel > *": 2, "#campaignsPanel > *": 4, "#board > *": 4, "#issuespanel > *": 1, "#feed > *": 1,
    "#agentsPanel > *": 2, "#cfgpre > *": 9,
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
  t("document.write", () => { document.write(s); });
})();
"""
CHEAT_SHAPES = ("markup called as a function", "put a string")  # refused by index.js itself, with or without Trusted Types
NO_TT_SHAPES = {"innerHTML", "computed innerHTML", "outerHTML", "insertAdjacentHTML", "createContextualFragment",
                "DOMParser", "srcdoc", "setHTMLUnsafe", "script text", "script src"}


# #7684: the trusted-markup token cannot be forged. Each attempt builds a host, tries to put raw markup there through a
# forged token, and records whether anything raw landed. None may, with or without Trusted Types enforcement.
FORGE_JS = """
window.__forge = {};
(function(){
  const RAW = "<img src=x onerror=window.__pwn=21><b>forged</b>";
  const attempt = (name, fn) => {
    const host = document.createElement("div"); document.body.appendChild(host);
    let how = "ran";
    try { fn(host); } catch (e) { how = "threw " + e.name; }
    window.__forge[name] = {how: how, raw: host.querySelector("img, b") !== null, html: host.innerHTML.slice(0, 60)};
  };
  attempt("constructor", host => { const H = markup`x`.constructor; put(host, new H(RAW)); });
  attempt(".s mutation", host => { const t = markup`x`; t.s = RAW; put(host, t); });
  attempt("prototype set", host => { const f = {s: RAW}; Object.setPrototypeOf(f, Object.getPrototypeOf(markup`x`)); put(host, f); });
  attempt("Object.create", host => { const f = Object.create(Object.getPrototypeOf(markup`x`)); f.s = RAW; put(host, f); });
  attempt("__proto__ literal", host => { const f = {__proto__: Object.getPrototypeOf(markup`x`), s: RAW}; put(host, f); });
  attempt("plain object with s", host => { put(host, {s: RAW}); });
  attempt("cat of a forged value", host => { put(host, cat([{s: RAW}])); });
  attempt("markup of a forged value", host => { put(host, markup`<p>${{s: RAW}}</p>`); });
  attempt("WeakMap methods patched", host => {
    const has0 = WeakMap.prototype.has, get0 = WeakMap.prototype.get;
    try { WeakMap.prototype.has = () => true; WeakMap.prototype.get = () => RAW; put(host, markup`<p>${RAW}</p>`); }
    finally { WeakMap.prototype.has = has0; WeakMap.prototype.get = get0; }
  });
})();
"""
FORGE_NAMES = ("constructor", ".s mutation", "prototype set", "Object.create", "__proto__ literal", "plain object with s",
               "cat of a forged value", "markup of a forged value", "WeakMap methods patched")


def assert_nothing_forged(testcase, result):
    forged = result["forge"]
    testcase.assertEqual(sorted(forged), sorted(FORGE_NAMES))
    testcase.assertEqual({name: f["html"] for name, f in forged.items() if f["raw"]}, {}, "raw markup landed through a forged token")
    testcase.assertEqual(result["pwn"], "undefined", "window.__pwn is %s" % result["pwn"])


def leaves(value, fn, path=()):
    if isinstance(value, dict):
        out = {k: leaves(v, fn, path + (k,)) for k, v in value.items()}
        out["createHTML"] = PAYLOAD
        out["__proto__"] = {"polluted": PAYLOAD, "createHTML": PAYLOAD}
        out["toString"] = PAYLOAD
        out["constructor"] = PAYLOAD
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


def mutate(text, old, new):
    """text.replace(old, new), refusing a replace that changes nothing (#7691: a no-op mutation proves nothing)."""
    assert text.count(old) >= 1, "the mutation target %r is not present, so the mutation would be a no-op" % old
    return text.replace(old, new)


def without(headers_text, directives):
    out = headers_text
    for directive in directives:
        out = mutate(out, "; " + directive, "")
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


def assert_clean(result, counts=None):
    """0 Trusted Types violations, 0 CSP violations, empty console, EMPTY log (no allowance for any message, #7688),
    no exception, nothing executed, panels rendered with the expected element counts."""
    assert result["v"] == [], "violations: %s" % result["v"]
    assert result["exceptions"] == [], "exceptions: %s" % result["exceptions"]
    assert result["console"] == [], "console: %s" % result["console"]
    assert result["log"] == [], "log: %s" % result["log"]
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
        self.assertNotIn("'unsafe-inline'", result["csp"], "the shipped CSP must not allow inline style (#7689)")
        self.assertIn("style-src 'self' https://fonts.googleapis.com;", result["csp"])
        self.assertFalse(result["live"].startswith("offline"), result["live"])

    def test_a_hostile_state_in_every_panel_is_inert_and_still_renders(self):
        text = hostile_text(self.state_json)
        self.assertIn("1e999", text)
        self.assertIn('"__proto__"', text)
        self.assertIn('"createHTML"', text)
        self.assertIn("javascript:window.__pwn=4", text)
        result = self.run_page(state_text=text)
        assert_clean(result, HOSTILE_PANELS)
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


class TokenForging7684(BrowserCase):
    """#7684: markup() returns a closure-private brand, not a type. A constructor, a mutated property or a set prototype
    must insert NOTHING raw, in a Trusted Types browser and in one without."""

    def test_no_forged_token_inserts_raw_markup(self):
        result = self.run_page(js_append=FORGE_JS)
        assert_nothing_forged(self, result)
        self.assertEqual(result["exceptions"], [])

    def test_no_forged_token_inserts_raw_markup_without_trusted_types_either(self):
        weak = without(HEADERS_TEXT, TT_DIRECTIVES)
        result = self.run_page(headers_text=weak, init_script=NoTrustedTypes7634.HIDE, js_append=FORGE_JS)
        self.assertEqual(result["tt"], "undefined")
        assert_nothing_forged(self, result)

    def test_the_constructor_and_prototype_attempts_throw_and_the_s_mutation_is_inert(self):
        forged = self.run_page(js_append=FORGE_JS)["forge"]
        for name in ("constructor", "prototype set", "Object.create", "__proto__ literal", "plain object with s"):
            self.assertTrue(forged[name]["how"].startswith("threw"), (name, forged[name]))
        self.assertEqual(forged[".s mutation"]["html"], "x", forged[".s mutation"])


class Hardening7690_7691(unittest.TestCase):
    """#7690: the README claims a hostile `constructor` key and a refused document.write sink; the tests must run both.
    #7691: a mutation that replaces nothing proves nothing."""

    def test_the_hostile_state_carries_a_constructor_key(self):
        text = hostile_text({"a": {"b": 1}})
        self.assertIn('"constructor"', text)
        self.assertIn('"__proto__"', text)

    def test_document_write_is_one_of_the_refused_sink_shapes(self):
        self.assertIn("document.write(s);", SHAPES_JS)
        self.assertIn('t("document.write"', SHAPES_JS)

    def test_the_readme_claims_match_what_the_tests_run(self):
        readme = (cdp.REPO / "infra" / "cf-dashboard" / "README.md").read_text(encoding="utf-8")
        claimed = [name for name in ("constructor", "document.write") if name in readme]
        self.assertEqual(claimed, ["constructor", "document.write"])
        for name in claimed:
            self.assertIn(name, SHAPES_JS + hostile_text({"a": 1}) + FORGE_JS, "the README claims %s, no test runs it" % name)

    def test_assert_clean_has_no_allowance_for_rendering_errors(self):
        import inspect
        self.assertEqual(list(inspect.signature(assert_clean).parameters), ["result", "counts"])
        self.assertEqual(assert_clean.__code__.co_consts.count("rendering/error:"), 0)

    def test_every_mutation_helper_refuses_a_replace_that_changes_nothing(self):
        helper = globals().get("mutate")
        self.assertIsNotNone(helper, "there is no mutate() helper that asserts its replace applied")
        with self.assertRaises(AssertionError):
            helper("abc", "zzz", "y")
        with self.assertRaises(AssertionError):
            without("abc", ("zzz",))
        self.assertEqual(helper("a b a", "a", "c"), "c b c")
        self.assertEqual(without("x; y; z", ("y",)), "x; z")

    def test_the_sinks_run_test_applies_its_mutation(self):
        import inspect
        source = inspect.getsource(MutationProofs7634.test_without_trusted_types_enforcement_the_sinks_run)
        self.assertNotIn('SHAPES_JS.replace(', source)
        self.assertIn("mutate(SHAPES_JS", source)


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
        result = self.run_page(headers_text=weak, js_append=mutate(SHAPES_JS, "document.write(s);", ""))
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
        assert_clean(result, HOSTILE_PANELS)


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
