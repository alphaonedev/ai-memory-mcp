#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""#6578 acceptance set: every bypass class of ``redact()`` found by the adversarial corpus.

THE DEFECT (#6578, reviewer comment 6096965761 and the follow-up fuzz).  ``redact()`` in
scripts/check_external_pr_approval.py matches a token shape literally (``gh[pousr]_`` /
``github_pat_`` / ``Bearer|Basic|token <value>``) and then percent-decodes.  Any transform
that keeps the secret recoverable but breaks the literal shape relays the secret's random
part into the public job log through ``workflow_error`` and the first ``gh`` stderr line
that ``gh_api`` relays.  The corpus that found these classes is the fuzz driver described
in #6578 (24,224 cases); this file pins one test per class, each red on
fix/6117-promo6-ssh-r5 @ e3c520bd3.

THE RULE.  No 8-character window of the secret's random part survives in the relayed line
in ANY decodable form: the line is checked raw and after each inverse transform
(percent, HTML entity, JSON/Python/Rust escapes, invisible-character strip, NFKC, base64
and hex runs).  The assertion is on the decoded output, never on the exact redacted text,
so it holds for a decode-then-redact fix and for a widened pattern alike.

CLASSES (one test each; the first is the reviewer's class, the rest are new):
  C1 in-line split by an encoded line break or whitespace (#6578 round 8).
  C2 in-line split by an invisible / control / ANSI sequence (not ``\\s``).
  C3 one prefix character re-encoded or substituted (JSON ``\\u``, HTML entity,
     fullwidth, confusable, upper case): the body stays verbatim.
  C4 the whole token re-encoded (JSON ``\\u``, HTML entities, base64, hex, UTF-16 as
     latin-1, ``\\x`` / ``\\u{}`` escaped reprs, fullwidth, NUL-interleaved).
  C5 an authorization scheme word joined to its value by ``=``, ``:`` or a JSON key.
  C6 a GitHub token immediately followed by another credential: the greedy body run
     swallows the next prefix or scheme word and the second secret is relayed.
  C7 no caller applies ``redact()`` per read chunk (a pin, green today; #7062 shape).

Stdlib only; Python 3.9+.  Synthetic tokens only.
"""

import base64
import html
import importlib.util
import re
import string
import sys
import types
import unicodedata
import unittest
import unittest.mock
import urllib.parse
from pathlib import Path
from typing import Callable, List, Optional

ROOT = Path(__file__).resolve().parents[2]
APPROVAL_PY = ROOT / "scripts" / "check_external_pr_approval.py"
REPO = "alphaonedev/ai-memory-mcp"
OPERATOR = "alphaonedev"
SHA = "a" * 40
WIDTH = 8
_ALPHABET = string.ascii_letters + string.digits

_B64_RUN = re.compile(r"[A-Za-z0-9+/=_-]{12,}")
_HEX_RUN = re.compile(r"[0-9A-Fa-f]{16,}")
_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_JSON_U = re.compile(r"\\u([0-9A-Fa-f]{4})")
_PY_X = re.compile(r"\\x([0-9A-Fa-f]{2})")
_RUST_U = re.compile(r"\\u\{([0-9A-Fa-f]{1,6})\}")
_INVISIBLE = re.compile("[\x00-\x1f\x7f\x85\u00a0\u00ad\u2000-\u200f\u2028\u2029\u202f\u205f\u2060\u3000\ufeff?\\s-]")


def _load_approval():
    spec = importlib.util.spec_from_file_location("check_external_pr_approval_6578", str(APPROVAL_PY))
    if spec is None or spec.loader is None:
        raise AssertionError("cannot load " + str(APPROVAL_PY))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _token_body(length: int, offset: int = 0) -> str:
    return "".join(_ALPHABET[(offset + 7 * i) % len(_ALPHABET)] for i in range(length))


def _windows(secret: str, text: str) -> List[str]:
    return [secret[i:i + WIDTH] for i in range(len(secret) - WIDTH + 1) if secret[i:i + WIDTH] in text]


def _b64_runs(text: str) -> List[str]:
    out = []
    for run in _B64_RUN.findall(text):
        run = run.replace("-", "+").replace("_", "/")
        for shift in (0, 1, 2, 3):
            chunk = run[shift:]
            chunk = chunk[: len(chunk) - len(chunk) % 4]
            if len(chunk) >= 12:
                try:
                    out.append(base64.b64decode(chunk).decode("latin-1"))
                except (ValueError, UnicodeDecodeError):
                    pass
    return out


def _hex_runs(text: str) -> List[str]:
    out = []
    for run in _HEX_RUN.findall(text):
        for shift in (0, 1):
            chunk = run[shift:]
            chunk = chunk[: len(chunk) - len(chunk) % 2]
            try:
                out.append(bytes.fromhex(chunk).decode("latin-1"))
            except ValueError:
                pass
    return out


def _decodable_forms(text: str) -> List[str]:
    """``text`` and every inverse transform a reader of the job log could apply."""
    unq = urllib.parse.unquote(text)
    forms = [text, unq, urllib.parse.unquote(unq), html.unescape(text), html.unescape(unq),
             _JSON_U.sub(lambda m: chr(int(m.group(1), 16)), text),
             _PY_X.sub(lambda m: chr(int(m.group(1), 16)), text),
             _RUST_U.sub(lambda m: chr(int(m.group(1), 16)), text),
             _ANSI.sub("", text), unicodedata.normalize("NFKC", text),
             _INVISIBLE.sub("", unq), _INVISIBLE.sub("", html.unescape(unq))]
    forms.extend(_b64_runs(text))
    forms.extend(_b64_runs(unq))
    forms.extend(_hex_runs(text))
    forms.extend(_hex_runs(unq))
    return forms


def _leaked(secret: str, text: str, inverse: Optional[Callable[[str], str]] = None) -> List[str]:
    """Every 8-character window of ``secret`` found in any decodable form of ``text``."""
    forms = _decodable_forms(text)
    if inverse is not None:
        forms.extend(_decodable_forms(inverse(text)))
    hits = []
    for form in forms:
        for w in _windows(secret, form):
            if w not in hits:
                hits.append(w)
    return hits


def _fullwidth(text: str) -> str:
    return "".join(chr(ord(c) + 0xFEE0) if 0x21 <= ord(c) <= 0x7E else c for c in text)


class _RedactCase(unittest.TestCase):
    """Shared harness: a carrier line goes through the escaper and through the gh relay."""

    def setUp(self) -> None:
        self.mod = _load_approval()

    def relayed(self, stderr_line: str) -> str:
        """The gate's output when ``gh`` fails with ``stderr_line`` as its first stderr line."""
        def fake_run(*_a, **_k):
            return types.SimpleNamespace(returncode=1, stdout="", stderr=stderr_line + "\n")
        with unittest.mock.patch.object(self.mod.subprocess, "run", fake_run):
            rc, lines = self.mod.run_gate("push", {}, REPO, SHA, OPERATOR, self.mod.gh_api)
        self.assertEqual(1, rc, lines)
        return "\n".join(lines)

    def assert_sealed(self, secret: str, carrier: str, inverse: Optional[Callable[[str], str]] = None) -> None:
        for entry, text in (("workflow_error", self.mod.workflow_error(carrier)),
                            ("gh_api relay", self.relayed(carrier))):
            hits = _leaked(secret, text, inverse)
            self.assertEqual([], hits, "%s relays %d window(s) of the secret, first %r, for carrier %r: %r"
                             % (entry, len(hits), hits[0] if hits else None, carrier[:60], text[:200]))

    def github_shapes(self):
        """(label, prefix, random part) for the GitHub shapes."""
        return [("ghp_", "ghp_", _token_body(36, 3)), ("ghs_", "ghs_", _token_body(36, 7)),
                ("ghu_", "ghu_", _token_body(36, 11)),
                ("github_pat_", "github_pat_", _token_body(22, 5) + "_" + _token_body(59, 13))]

    def scheme_shapes(self):
        """(scheme word, opaque value) for the authorization shapes."""
        jwt = "eyJ" + _token_body(17, 2) + "." + "eyJ" + _token_body(40, 9) + "." + _token_body(43, 4)
        basic = base64.b64encode(("user:" + _token_body(24, 6)).encode()).decode()
        hexpat = "".join("0123456789abcdef"[(3 + 5 * i) % 16] for i in range(40))
        return [("Bearer", jwt), ("Basic", basic), ("token", hexpat)]


def _drop(sep: str) -> Callable[[str], str]:
    def inverse(text: str) -> str:
        text = html.unescape(urllib.parse.unquote(text))
        return text.replace(sep, "").replace(urllib.parse.quote(sep), "")
    return inverse


class InLineSplitByEncodedBreakOrWhitespace6578(_RedactCase):
    """C1 (#6578 round 8): a GitHub token split inside one line by an encoded line break,
    a backslash-escaped break, an HTML break entity, whitespace or a hyphenated encoded
    break is relayed from the break onwards.  Offsets 4, 12 and 20 into the token."""

    SEPARATORS = {"pct0A": "%0A", "pct0D0A": "%0D%0A", "pct250A": "%250A", "bs-n": "\\n", "bs-r-n": "\\r\\n",
                  "amp10": "&#10;", "ampx0a": "&#x0a;", "space": " ", "tab": "\t", "pct20": "%20",
                  "nbsp": "\u00a0", "en-space": "\u2002", "ideographic-space": "\u3000", "hyphen-pct0A": "-%0A"}

    def test_6578_c1_split_by_encoded_break_or_whitespace(self) -> None:
        for label, prefix, secret in self.github_shapes():
            token = prefix + secret
            for name, sep in self.SEPARATORS.items():
                for offset in (len(prefix), len(prefix) + 8, len(prefix) + 16):
                    with self.subTest(shape=label, sep=name, offset=offset):
                        self.assert_sealed(secret, token[:offset] + sep + token[offset:], _drop(sep))


class InLineSplitByInvisibleOrControl6578(_RedactCase):
    """C2: a split by a zero-width / format character, a NUL or other control byte, or an
    ANSI escape sequence.  None of these is ``\\s``, so a whitespace-stripping fix does
    not see through them; the fragment after the split is relayed."""

    SEPARATORS = {"ZWSP": "\u200b", "ZWNJ": "\u200c", "ZWJ": "\u200d", "BOM": "\ufeff", "soft-hyphen": "\u00ad",
                  "word-joiner": "\u2060", "pctE2808B": "%E2%80%8B", "amp8203": "&#8203;",
                  "NUL": "\x00", "BS": "\x08", "DEL": "\x7f", "sgr-reset": "\x1b[0m", "sgr-red": "\x1b[31m",
                  "cursor-up": "\x1b[1A"}

    def test_6578_c2_split_by_invisible_control_or_ansi(self) -> None:
        for label, prefix, secret in self.github_shapes():
            token = prefix + secret
            for name, sep in self.SEPARATORS.items():
                for offset in (len(prefix), len(prefix) + 8, len(prefix) + 16):
                    with self.subTest(shape=label, sep=name, offset=offset):
                        self.assert_sealed(secret, token[:offset] + sep + token[offset:], _drop(sep))


class PrefixCharacterReencodedOrSubstituted6578(_RedactCase):
    """C3: one character of the prefix is re-encoded (JSON ``\\u``, HTML entity, fullwidth)
    or substituted (a Unicode confusable, upper case).  The literal prefix match fails and
    the 36-character body is relayed verbatim.  A known prefix is the only signal
    ``redact()`` has, so every spelling of it a log can carry must be recognised."""

    CONFUSABLE = {"g": "\u0261", "h": "\u04bb", "p": "\u0440", "s": "\u0455", "u": "\u057d", "_": "\uff3f",
                  "i": "\u0456", "t": "\u0442", "a": "\u0430", "b": "\u042c"}

    def test_6578_c3_prefix_character_reencoded(self) -> None:
        for label, prefix, secret in self.github_shapes():
            for i, ch in enumerate(prefix):
                tail = prefix[i + 1:] + secret
                for name, spelled, inverse in (
                        ("json-u", "\\u%04x" % ord(ch), lambda t: _JSON_U.sub(lambda m: chr(int(m.group(1), 16)), t)),
                        ("html-dec", "&#%d;" % ord(ch), html.unescape),
                        ("html-hex", "&#x%x;" % ord(ch), html.unescape),
                        ("fullwidth", _fullwidth(ch), lambda t: unicodedata.normalize("NFKC", t))):
                    with self.subTest(shape=label, at=i, form=name):
                        self.assert_sealed(secret, prefix[:i] + spelled + tail, inverse)

    def test_6578_c3_prefix_character_substituted(self) -> None:
        for label, prefix, secret in self.github_shapes():
            for i, ch in enumerate(prefix):
                if ch in self.CONFUSABLE:
                    with self.subTest(shape=label, at=i, form="confusable"):
                        self.assert_sealed(secret, prefix[:i] + self.CONFUSABLE[ch] + prefix[i + 1:] + secret)
            for name, spelled in (("upper", prefix.upper()), ("title", prefix.title()), ("swapcase", prefix.swapcase())):
                with self.subTest(shape=label, form=name):
                    self.assert_sealed(secret, spelled + secret)


class WholeTokenReencoded6578(_RedactCase):
    """C4: the whole token arrives in another reversible encoding.  ``redact()`` only
    percent-decodes, so every other encoding carries the body through unredacted."""

    def test_6578_c4_whole_token_reencoded(self) -> None:
        def json_u(t: str) -> str:
            return "".join("\\u%04x" % ord(c) for c in t)

        def rust_u(t: str) -> str:
            return "Some(\"" + "".join("\\u{%x}" % ord(c) for c in t) + "\")"

        def b64_runs(t: str) -> str:
            return "\n".join(_b64_runs(t))

        def hex_runs(t: str) -> str:
            return "\n".join(_hex_runs(t))

        def strip_nul(t: str) -> str:
            return t.replace("\x00", "").replace("?", "")

        forms = [
            ("json-u-all", json_u, lambda t: _JSON_U.sub(lambda m: chr(int(m.group(1), 16)), t)),
            ("html-dec-all", lambda t: "".join("&#%d;" % ord(c) for c in t), html.unescape),
            ("html-hex-all", lambda t: "".join("&#x%x;" % ord(c) for c in t), html.unescape),
            ("base64-token", lambda t: base64.b64encode(t.encode()).decode(), b64_runs),
            ("base64url-token", lambda t: base64.urlsafe_b64encode(t.encode()).decode().rstrip("="), b64_runs),
            ("base64-line", lambda t: base64.b64encode(("HTTP 401 for " + t + " (end)").encode()).decode(), b64_runs),
            ("hex-token", lambda t: t.encode().hex(), hex_runs),
            ("hex-upper-token", lambda t: t.encode().hex().upper(), hex_runs),
            ("utf16le-as-latin1", lambda t: t.encode("utf-16-le").decode("latin-1"), strip_nul),
            ("utf16be-as-latin1", lambda t: t.encode("utf-16-be").decode("latin-1"), strip_nul),
            ("python-bytes-hex-repr", lambda t: "b'" + "".join("\\x%02x" % ord(c) for c in t) + "'",
             lambda t: _PY_X.sub(lambda m: chr(int(m.group(1), 16)), t)),
            ("rust-debug-u-escapes", rust_u, lambda t: _RUST_U.sub(lambda m: chr(int(m.group(1), 16)), t)),
            ("fullwidth-all", _fullwidth, lambda t: unicodedata.normalize("NFKC", t)),
            ("nul-every-4", lambda t: "\x00".join(t[i:i + 4] for i in range(0, len(t), 4)), strip_nul),
        ]
        for label, prefix, secret in self.github_shapes():
            for name, encode, inverse in forms:
                with self.subTest(shape=label, form=name):
                    self.assert_sealed(secret, encode(prefix + secret), inverse)


class AuthorizationSchemeSeparator6578(_RedactCase):
    """C5: ``Bearer`` / ``Basic`` / ``token`` joined to a long opaque value by ``=``, ``:``,
    ``: ``, a JSON key or a backslash-escaped break instead of whitespace.  The third
    TOKEN_RE alternative requires ``\\s+`` after the scheme word, so the value is relayed.
    (#7055 is the whitespace-split sibling of this class; #6638's 7-character prose
    control is untouched: every value here is at least 20 characters.)"""

    def test_6578_c5_scheme_separator_variants(self) -> None:
        for scheme, value in self.scheme_shapes():
            for name, carrier in (("equals", scheme + "=" + value), ("colon", scheme + ":" + value),
                                  ("colon-space", scheme + ": " + value),
                                  ("json-key", '{"' + scheme.lower() + '":"' + value + '"}'),
                                  ("escaped-break-text", scheme + "\\n" + value)):
                with self.subTest(scheme=scheme, form=name):
                    self.assert_sealed(value, carrier)


class AdjacentCredentialSwallowed6578(_RedactCase):
    """C6: ``gh[pousr]_[A-Za-z0-9]+`` is greedy.  When another credential follows a GitHub
    token with no separator, the body run swallows the next prefix letters or scheme word
    (``ghp_<body>ghs`` / ``ghp_<body>Bearer``); what remains (``_<body2>`` or the JWT) is
    no longer a token shape and is relayed whole."""

    def test_6578_c6_adjacent_github_token(self) -> None:
        first = "ghp_" + _token_body(36, 21)
        for label, prefix, secret in self.github_shapes():
            with self.subTest(shape=label):
                self.assert_sealed(secret, first + prefix + secret)

    def test_6578_c6_adjacent_scheme_value(self) -> None:
        first = "ghp_" + _token_body(36, 21)
        for scheme, value in self.scheme_shapes():
            with self.subTest(scheme=scheme):
                self.assert_sealed(value, first + scheme + " " + value)


class NoPerChunkRedaction6578(unittest.TestCase):
    """C7 pin (green today): ``redact()`` is applied to whole captured text, never per read
    chunk, so a token cannot straddle a chunk boundary (the #7062 shape in sdk-python-live.py).
    ``gh_api`` captures with ``capture_output=True`` and redacts the first stderr line."""

    def test_6578_c7_no_chunked_reader_feeds_redact(self) -> None:
        src = APPROVAL_PY.read_text(encoding="utf-8")
        self.assertNotRegex(src, r"\.read\([0-9]", "a sized read() chunks text before redact()")
        self.assertNotRegex(src, r"\.read1\(", "a read1() chunks text before redact()")
        self.assertIn("capture_output=True", src)
        self.assertRegex(src, r"splitlines\(\) or \[\"\"\]\)\[0\]\n\s+first = redact\(first\)")


if __name__ == "__main__":
    sys.exit(unittest.main(verbosity=2))
