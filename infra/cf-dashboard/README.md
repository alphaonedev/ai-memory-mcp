# cf-dashboard

The static Cloudflare Pages dashboard (`public/`) and the scripts that publish its state (`push-state.py`, `deploy.py`,
`hostscrub.py`). The dashboard is operator-internal: it shows fleet state to the operator, it is not a public product
surface.

## What protects the page from injected markup

The state file is data from the fleet. `public/index.js` renders it, and the protection has three layers.

1. **Escaping.** Every dynamic value goes through the `markup` tagged template, which escapes each interpolation that
   is not already `markup` output (`&`, `<`, `>`, `"`, `'`). `markup` works only as a tag; calling it as a function
   throws. The one function that writes HTML, `put(host, markup)`, takes markup only and throws on a string.
2. **`script-src 'self'`.** No inline script, no event-handler attribute and no `javascript:` URL can run, in any
   browser.
3. **Trusted Types, enforced by the browser.** The CSP carries `require-trusted-types-for 'script'; trusted-types dash`.
   The page creates exactly one policy, `dash`, inside the closure that defines `put`. Its `createHTML` escapes any
   plain string and passes through only the closure-private `Html` class. A script that assigns a string to
   `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `srcdoc` and the like is refused by the browser,
   and so is a second `createPolicy`.

### What is and is not claimed

- Chromium-based browsers enforce Trusted Types. The browser test (`scripts/ci/tests/test_cf_browser_7634.py`)
  proves it in a real Chrome: 0 Trusted Types violations, 0 CSP violations, an empty console and every panel
  populated for a normal state; a hostile state in every panel (markup values, the keys `createHTML`, `__proto__`,
  `toString`, `constructor`, `javascript:` values, `1e999`) executes nothing.
- Firefox and Safari ignore the Trusted Types directives. They get the escaping (layer 1) and `script-src 'self'`
  (layer 2). That is the whole claim there; the page also loads and renders with `window.trustedTypes` undefined
  (tested).
- A static source guard (`scripts/ci/tests/cf_xss_guard_7587.py`) allowlists the only sink: one
  `createPolicy('dash', ...)`, one `.createHTML(` call, both inside `put`. A computed property access such as
  `el['inner'+'HTML']` is invisible to a static scan; the browser enforcement and the browser test cover it.
- The checker below **fails closed and may falsely refuse**: a safe change can be refused until the table is widened
  on purpose.

## Checks

| Check | File | Role |
| --- | --- | --- |
| CSP and page allowlist | `scripts/ci/tests/cf_csp_allowlist_7313.py`, `test_cf_csp_allowlist_7636.py` | per-directive table, refuses everything not listed |
| JS sink allowlist | `scripts/ci/tests/cf_xss_guard_7587.py`, `test_cf_xss_7587.py` | one policy, one `createHTML`, tagged `markup` only |
| Browser test | `scripts/ci/tests/test_cf_browser_7634.py` (harness `cf_cdp_7313.py`) | real Chrome over CDP, standard library only |

The browser test drives the installed Chrome or Chromium (`CF_DASH_CHROME`, then `google-chrome`, `chromium`, then the
Playwright cache). Without a browser it skips, except when `CF_DASH_REQUIRE_BROWSER=1`, which CI sets: there a missing
browser fails.

## Widening the CSP allowlist

The shipped policy is `public/_headers`. `cf_csp_allowlist_7313.py` accepts only the directives and tokens in its
tables and refuses the rest; every refusal names the directive, the file to edit and this section.

| Directive | Tokens allowed |
| --- | --- |
| `default-src` | `'self'` |
| `script-src` | `'self'` |
| `style-src` | `'self'`, `'unsafe-inline'` (the documented exception), `https://fonts.googleapis.com` |
| `font-src` | `https://fonts.gstatic.com` |
| `img-src` | `'self'`, `data:` |
| `connect-src` | `'self'` |
| `base-uri`, `form-action`, `object-src`, `frame-ancestors` | `'none'` |
| `require-trusted-types-for` | `'script'` |
| `trusted-types` | `dash` |

Required: `default-src`, `script-src`, `object-src`, `base-uri`, `require-trusted-types-for`, `trusted-types`. Also
refused: a duplicate or empty directive, a comma (a second policy in one value), and anything but exactly one CSP value
per served path.

To widen it: change `_headers`, then add the directive or token to `ALLOWED_DIRECTIVES` (and `LOAD_ALLOW` /
`LOAD_NEEDS` for a new load origin) in the same commit, add a test row to `test_cf_csp_allowlist_7636.py` that pins the
new shape as accepted, and say why in the commit message. Wildcards and the site's own host name are refused as "not
in the table"; that is a possible false refusal, not a bug.

### The `style-src 'unsafe-inline'` exception

The only documented `'unsafe-inline'`. The pages carry `<style>` blocks and `index.js` sets dynamic style attributes
(bar widths, colours). Style cannot run script while `script-src` has no `'unsafe-inline'`, and the checker refuses a
backslash in CSS. Removing it means moving every dynamic style into a stylesheet or the CSSOM.

### Page markup rules

The page check parses with `html.parser`, decodes entities (up to four passes) and strips whitespace and zero-width
characters before testing a URL scheme. It refuses `<base>`, `<math>`, frames, objects, forms, `<meta http-equiv>`,
inline `<script>`, `on*` attributes, `srcset`, and `javascript:` / `vbscript:` in any spelling. `data-src` is not
`src`. A static `<svg>` is accepted only when it is empty (the ring gauge is an empty `<svg id="ringsvg">` that
`index.js` fills); an `<svg>` with content is refused.
