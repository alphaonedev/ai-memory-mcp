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
   plain string and passes through only a token that a closure-private `WeakMap` holds (#7684): `markup` returns a
   frozen, prototype-less, property-less token and keeps its text in that map, so no constructor, property or
   prototype game can mint one, and patching `WeakMap.prototype` afterwards changes nothing (the methods are captured
   at load). The static guard refuses, outside the helper block, any name of the internals and any use of
   `setPrototypeOf`, `__proto__`, `Object.create` or `.constructor`. A script that assigns a string to
   `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `srcdoc` and the like is refused by the browser,
   and so is a second `createPolicy`.

### What is and is not claimed

- Chromium-based browsers enforce Trusted Types. The browser test (`scripts/ci/tests/test_cf_browser_7634.py`)
  proves it in a real Chrome: 0 Trusted Types violations, 0 CSP violations, an empty console and every panel
  populated for a normal state; a hostile state in every panel (markup values, the keys `createHTML`, `__proto__`,
  `toString`, `constructor`, `javascript:` values, `1e999`) executes nothing, logs nothing (the console and the log
  are asserted empty with no allowance) and renders pinned element counts. The sink test also runs `document.write`,
  and three token-forging attempts (a constructor, a mutated property, a set prototype) insert nothing raw.
- Every number written into an SVG attribute or path goes through one helper (`sn`/`pd`) that requires
  `Number.isFinite`; a non-finite value omits that element (a text placeholder outside SVG).
- There is no inline style: the pages link `index.css` / `vv.css`, dynamic widths use `data-w` / `data-left` applied
  with `style.setProperty`, and the shipped CSP has no `'unsafe-inline'`; the browser test proves 0 CSP violations.
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
| `style-src` | `'self'`, `https://fonts.googleapis.com` |
| `font-src` | `https://fonts.gstatic.com` |
| `img-src` | `'self'`, `data:` |
| `connect-src` | `'self'` |
| `base-uri`, `form-action`, `object-src`, `frame-ancestors` | `'none'` |
| `require-trusted-types-for` | `'script'` |
| `trusted-types` | `dash` |

`_headers` is read by ONE parser, `cf_headers_7313.py`, used by the checker, the browser test server and every other
reader (#7685, #7686). It refuses, with the line number: a `!` removal line, a pattern that is not a plain path (a host
or scheme rule), a non-ASCII byte, and a second `Content-Security-Policy`. CSP directives split only on ASCII
whitespace, so a non-breaking space inside a directive is a refusal, not a token.

Required: `default-src`, `script-src`, `object-src`, `base-uri`, `require-trusted-types-for`, `trusted-types`. Also
refused: a duplicate or empty directive, a comma (a second policy in one value), and anything but exactly one CSP value
per served path.

To widen it: change `_headers`, then add the directive or token to `ALLOWED_DIRECTIVES` (and `LOAD_ALLOW` /
`LOAD_NEEDS` for a new load origin) in the same commit, add a test row to `test_cf_csp_allowlist_7636.py` that pins the
new shape as accepted, and say why in the commit message. Wildcards and the site's own host name are refused as "not
in the table"; that is a possible false refusal, not a bug.

### No `'unsafe-inline'` (#7689)

`DOCUMENTED_EXCEPTIONS` is empty. The pages carry no `<style>` block and no `style` attribute; the checker refuses
both, and a local stylesheet a page links is checked under the same policy (it may fetch only what a page may).

### Page markup rules

The page check parses with `html.parser`, decodes entities (up to four passes) and strips whitespace and zero-width
characters before testing a URL scheme. It refuses `<base>`, `<math>`, frames, objects, forms, `<meta http-equiv>`,
inline `<script>`, `on*` attributes, `srcset`, and `javascript:` / `vbscript:` in any spelling. `data-src` is not
`src`. A static `<svg>` is accepted only when it is empty (the ring gauge is an empty `<svg id="ringsvg">` that
`index.js` fills); an `<svg>` with content is refused.
