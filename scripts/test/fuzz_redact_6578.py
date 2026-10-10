#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""#6578 adversarial corpus for ``redact()`` in scripts/check_external_pr_approval.py.

Generates, for every secret shape the function recognises (GitHub ``gh[pousr]_`` and
``github_pat_`` tokens, HTTP ``Bearer`` / ``Basic`` / ``token`` authorization values),
a corpus of transformed carrier lines and feeds each line to the three entry points
that reach the public job log:

  * ``redact(line)``                       the function itself
  * ``workflow_error(line)``               the ``::error::`` escaper (redact + control + percent)
  * ``gh_api`` relay                       ``proc.stderr.strip().splitlines()[0]`` -> redact -> [:300]
                                           -> GateError -> workflow_error (fake ``subprocess.run``)

A case is BAD when the output still holds >= 8 consecutive characters of the secret's
random part in any decodable form: the output is passed through the inverse of the
transform that built the case (and through a fixed set of generic decoders) before the
window check.  Synthetic tokens only; nothing here is a real credential.

Usage (stdlib only, Python 3.9+):

    python3 -I .local-runs/6578/fuzz_redact.py --script <path>/scripts/check_external_pr_approval.py \
        [--json out.json] [--examples 3] [--relay]

Exit status 0 always: the corpus is a report, not a gate.
"""

import argparse
import base64
import html
import importlib.util
import json
import re
import string
import subprocess
import sys
import types
import unicodedata
import unittest.mock
import urllib.parse
from pathlib import Path

WIDTH = 8
ALPHABET = string.ascii_letters + string.digits


def body(length, offset=0):
    """Deterministic synthetic token body (same construction as the 5447 tests)."""
    return "".join(ALPHABET[(offset + 7 * i) % len(ALPHABET)] for i in range(length))


def windows(secret, text, width=WIDTH):
    return [secret[i:i + width] for i in range(len(secret) - width + 1) if secret[i:i + width] in text]


# ---------------------------------------------------------------------------------------
# Secret shapes: (name, carrier text, secret random part)
# ---------------------------------------------------------------------------------------

def shapes():
    out = []
    for n, p in enumerate(("ghp", "gho", "ghu", "ghs", "ghr")):
        b = body(36, n)
        out.append((p + "_", p + "_" + b, b))
    pat = body(22, 5) + "_" + body(59, 11)
    out.append(("github_pat_", "github_pat_" + pat, pat))
    jwt = "eyJ" + body(17, 2) + "." + "eyJ" + body(40, 9) + "." + body(43, 4)
    out.append(("Bearer", "Bearer " + jwt, jwt))
    basic = base64.b64encode(("user:" + body(24, 6)).encode()).decode()
    out.append(("Basic", "Basic " + basic, basic))
    hexpat = "".join("0123456789abcdef"[(3 + 5 * i) % 16] for i in range(40))
    out.append(("token", "token " + hexpat, hexpat))
    return out


# ---------------------------------------------------------------------------------------
# Generic decoders applied to every output (plus the transform's own inverse)
# ---------------------------------------------------------------------------------------

_B64_RUN = re.compile(r"[A-Za-z0-9+/=_-]{12,}")
_HEX_RUN = re.compile(r"[0-9A-Fa-f]{16,}")
_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_JSON_U = re.compile(r"\\u([0-9A-Fa-f]{4})")
_PY_X = re.compile(r"\\x([0-9A-Fa-f]{2})")
_RUST_U = re.compile(r"\\u\{([0-9A-Fa-f]{1,6})\}")
_DROP = re.compile("[\x00-\x1f\x7f\x85\u00a0\u00ad\u2000-\u200f\u2028\u2029\u202f\u205f\u2060\u3000\ufeff?\\s-]")


def _b64_runs(text):
    found = []
    for run in _B64_RUN.findall(text):
        run = run.replace("-", "+").replace("_", "/")
        for shift in (0, 1, 2, 3):
            chunk = run[shift:]
            chunk = chunk[: len(chunk) - len(chunk) % 4]
            if len(chunk) < 12:
                continue
            try:
                found.append(base64.b64decode(chunk, validate=False).decode("latin-1"))
            except (ValueError, UnicodeDecodeError):
                pass
    return found


def _hex_runs(text):
    found = []
    for run in _HEX_RUN.findall(text):
        for shift in (0, 1):
            chunk = run[shift:]
            chunk = chunk[: len(chunk) - len(chunk) % 2]
            try:
                found.append(bytes.fromhex(chunk).decode("latin-1"))
            except ValueError:
                pass
    return found


def generic_decodes(text):
    """Every generic decodable form of ``text`` (the text itself first)."""
    forms = [text]
    unq = urllib.parse.unquote(text)
    forms.append(unq)
    forms.append(urllib.parse.unquote(unq))
    forms.append(html.unescape(text))
    forms.append(html.unescape(unq))
    forms.append(_JSON_U.sub(lambda m: chr(int(m.group(1), 16)), text))
    forms.append(_PY_X.sub(lambda m: chr(int(m.group(1), 16)), text))
    forms.append(_RUST_U.sub(lambda m: chr(int(m.group(1), 16)), text))
    forms.append(_ANSI.sub("", text))
    forms.append(unicodedata.normalize("NFKC", text))
    forms.append(_DROP.sub("", unq))
    forms.append(_DROP.sub("", html.unescape(unq)))
    forms.append(text.lower())
    forms.extend(_b64_runs(text))
    forms.extend(_b64_runs(unq))
    forms.extend(_hex_runs(text))
    forms.extend(_hex_runs(unq))
    return forms


def leaked(secret, output, inverse=None):
    """The first 8-character window of ``secret`` found in any decodable form of ``output``."""
    forms = generic_decodes(output)
    if inverse is not None:
        try:
            forms.extend(generic_decodes(inverse(output)))
        except (ValueError, UnicodeError):
            pass
    for form in forms:
        hit = windows(secret, form)
        if hit:
            return hit[0]
    return None


# ---------------------------------------------------------------------------------------
# Transforms: (class, name, fn(token) -> carrier text, inverse(output) -> text or None)
# ---------------------------------------------------------------------------------------

def _drop(sep):
    """Inverse for a split: remove the separator (and its percent/entity spellings)."""
    def inverse(out):
        text = urllib.parse.unquote(out)
        text = html.unescape(text)
        return text.replace(sep, "").replace(urllib.parse.quote(sep), "")
    return inverse


SPLIT_CLASSES = [
    ("split-literal-break", {"LF": "\n", "CRLF": "\r\n", "CR": "\r"}),
    ("split-escaped-break-text", {"bs-n": "\\n", "bs-r-n": "\\r\\n", "bs-r": "\\r"}),
    ("split-percent-break", {"pct0A": "%0A", "pct0D0A": "%0D%0A", "pct250A": "%250A", "pct0D": "%0D"}),
    ("split-html-entity-break", {"amp10": "&#10;", "ampx0a": "&#x0a;", "amp13": "&#13;", "ampNewLine": "&NewLine;"}),
    ("split-whitespace", {"space": " ", "tab": "\t", "VT": "\x0b", "FF": "\x0c", "pct20": "%20", "pct09": "%09",
                          "amp32": "&#32;", "nbsp": "\u00a0", "en-space": "\u2002", "em-space": "\u2003",
                          "thin-space": "\u2009", "ideographic-space": "\u3000", "pctC2A0": "%C2%A0"}),
    ("split-zero-width", {"ZWSP": "\u200b", "ZWNJ": "\u200c", "ZWJ": "\u200d", "BOM": "\ufeff",
                          "soft-hyphen": "\u00ad", "word-joiner": "\u2060", "pctE2808B": "%E2%80%8B",
                          "amp8203": "&#8203;"}),
    ("split-control", {"NUL": "\x00", "FS": "\x1c", "NEL": "\x85", "LS": "\u2028", "PS": "\u2029",
                       "BS": "\x08", "DEL": "\x7f"}),
    ("split-ansi", {"sgr-reset": "\x1b[0m", "sgr-red": "\x1b[31m", "cursor": "\x1b[1A"}),
    ("split-hyphenation", {"hyphen-LF": "-\n", "hyphen-CRLF": "-\r\n", "hyphen-pct0A": "-%0A"}),
]


def split_transforms():
    for cls, seps in SPLIT_CLASSES:
        for name, sep in seps.items():
            yield cls, name, sep


def _json_u(text):
    return "".join("\\u%04x" % ord(c) for c in text)


def _json_u_inverse(out):
    return _JSON_U.sub(lambda m: chr(int(m.group(1), 16)), out)


def _html_dec(text):
    return "".join("&#%d;" % ord(c) for c in text)


def _html_hex(text):
    return "".join("&#x%x;" % ord(c) for c in text)


def _pct_all(text):
    return "".join("%%%02X" % ord(c) for c in text)


def _fullwidth(text):
    return "".join(chr(ord(c) + 0xFEE0) if 0x21 <= ord(c) <= 0x7E else c for c in text)


def _utf16le(text):
    return text.encode("utf-16-le").decode("latin-1")


def _utf16be(text):
    return text.encode("utf-16-be").decode("latin-1")


def _b64(text):
    return base64.b64encode(text.encode()).decode()


def _b64url(text):
    return base64.urlsafe_b64encode(text.encode()).decode().rstrip("=")


def _hex(text):
    return text.encode().hex()


def _py_bytes_hex_repr(text):
    return "b'" + "".join("\\x%02x" % ord(c) for c in text) + "'"


def _rust_u(text):
    return "Some(\"" + "".join("\\u{%x}" % ord(c) for c in text) + "\")"


CONFUSABLE = {"g": "\u0261", "h": "\u04bb", "p": "\u0440", "o": "\u043e", "u": "\u057d", "s": "\u0455",
              "r": "\u0433", "_": "\uff3f", "i": "\u0456", "t": "\u0442", "a": "\u0430", "b": "\u042c",
              "e": "\u0435", "B": "\u0412", "n": "\u0578"}


def prefix_len(token):
    """Characters before the random part begins (``ghp_``, ``github_pat_``, ``Bearer ``...)."""
    for p in ("github_pat_", "Bearer ", "Basic ", "token "):
        if token.startswith(p):
            return len(p)
    return 4


def prefix_obfuscation_transforms():
    """(class, name, fn(token) -> text, inverse)"""
    def letter_json(i):
        def fn(token):
            n = prefix_len(token)
            if i >= n:
                return None
            return token[:i] + "\\u%04x" % ord(token[i]) + token[i + 1:]
        return fn

    def letter_html(i):
        def fn(token):
            n = prefix_len(token)
            if i >= n:
                return None
            return token[:i] + "&#%d;" % ord(token[i]) + token[i + 1:]
        return fn

    def letter_pct(i):
        def fn(token):
            n = prefix_len(token)
            if i >= n:
                return None
            return token[:i] + "%%%02X" % ord(token[i]) + token[i + 1:]
        return fn

    def letter_confusable(i):
        def fn(token):
            n = prefix_len(token)
            if i >= n or token[i] not in CONFUSABLE:
                return None
            return token[:i] + CONFUSABLE[token[i]] + token[i + 1:]
        return fn

    def letter_fullwidth(i):
        def fn(token):
            n = prefix_len(token)
            if i >= n:
                return None
            return token[:i] + _fullwidth(token[i]) + token[i + 1:]
        return fn

    def case_upper_prefix(token):
        n = prefix_len(token)
        return token[:n].upper() + token[n:]

    def case_title_prefix(token):
        n = prefix_len(token)
        return token[:n].title() + token[n:]

    def case_swap_prefix(token):
        n = prefix_len(token)
        return token[:n].swapcase() + token[n:]

    def whole_prefix_json(token):
        n = prefix_len(token)
        return _json_u(token[:n]) + token[n:]

    def whole_prefix_html(token):
        n = prefix_len(token)
        return _html_dec(token[:n]) + token[n:]

    def whole_prefix_fullwidth(token):
        n = prefix_len(token)
        return _fullwidth(token[:n]) + token[n:]

    for i in range(11):
        yield "prefix-json-escape", "json-u-at-%d" % i, letter_json(i), _json_u_inverse
        yield "prefix-html-entity", "html-dec-at-%d" % i, letter_html(i), html.unescape
        yield "prefix-percent-encoded", "pct-at-%d" % i, letter_pct(i), urllib.parse.unquote
        yield "prefix-confusable", "confusable-at-%d" % i, letter_confusable(i), None
        yield "prefix-fullwidth", "fullwidth-at-%d" % i, letter_fullwidth(i), lambda o: unicodedata.normalize("NFKC", o)
    yield "prefix-json-escape", "json-u-whole-prefix", whole_prefix_json, _json_u_inverse
    yield "prefix-html-entity", "html-dec-whole-prefix", whole_prefix_html, html.unescape
    yield "prefix-fullwidth", "fullwidth-whole-prefix", whole_prefix_fullwidth, lambda o: unicodedata.normalize("NFKC", o)
    yield "prefix-case", "upper-prefix", case_upper_prefix, None
    yield "prefix-case", "title-prefix", case_title_prefix, None
    yield "prefix-case", "swapcase-prefix", case_swap_prefix, None


def whole_reencoding_transforms():
    yield "whole-json-escape", "json-u-all", _json_u, _json_u_inverse
    yield "whole-html-entity", "html-dec-all", _html_dec, html.unescape
    yield "whole-html-entity", "html-hex-all", _html_hex, html.unescape
    yield "whole-percent-encoded", "pct-all", _pct_all, urllib.parse.unquote
    yield "whole-percent-encoded", "pct-all-twice", lambda t: _pct_all(_pct_all(t)), lambda o: urllib.parse.unquote(urllib.parse.unquote(o))
    yield "whole-base64", "b64-token", _b64, lambda o: "\n".join(_b64_runs(o))
    yield "whole-base64", "b64url-token", _b64url, lambda o: "\n".join(_b64_runs(o))
    yield "whole-base64", "b64-line", lambda t: _b64("HTTP 401 for " + t + " (end)"), lambda o: "\n".join(_b64_runs(o))
    yield "whole-hex", "hex-token", _hex, lambda o: "\n".join(_hex_runs(o))
    yield "whole-hex", "hex-upper-token", lambda t: _hex(t).upper(), lambda o: "\n".join(_hex_runs(o))
    yield "whole-utf16-as-latin1", "utf16le", _utf16le, lambda o: o.replace("\x00", "").replace("?", "")
    yield "whole-utf16-as-latin1", "utf16be", _utf16be, lambda o: o.replace("\x00", "").replace("?", "")
    yield "whole-python-repr", "bytes-plain-repr", lambda t: repr(t.encode()), None
    yield "whole-python-repr", "bytes-hex-repr", _py_bytes_hex_repr, lambda o: _PY_X.sub(lambda m: chr(int(m.group(1), 16)), o)
    yield "whole-rust-debug", "some-str", lambda t: "Some(\"" + t + "\")", None
    yield "whole-rust-debug", "some-u-escapes", _rust_u, lambda o: _RUST_U.sub(lambda m: chr(int(m.group(1), 16)), o)
    yield "whole-fullwidth", "fullwidth-all", _fullwidth, lambda o: unicodedata.normalize("NFKC", o)
    yield "whole-ansi-wrapped", "sgr-around", lambda t: "\x1b[31m" + t + "\x1b[0m", lambda o: _ANSI.sub("", o)
    yield "whole-yaml", "block-literal", lambda t: "token: |\n  " + t + "\n", None
    yield "whole-yaml", "block-folded-wrapped", lambda t: "token: >\n  " + t[:20] + "\n  " + t[20:] + "\n", lambda o: o.replace("\n  ", "")
    yield "whole-null-embedded", "nul-after-prefix", lambda t: t[:prefix_len(t)] + "\x00" + t[prefix_len(t):], lambda o: o.replace("\x00", "").replace("?", "")
    yield "whole-null-embedded", "nul-every-4", lambda t: "\x00".join(t[i:i + 4] for i in range(0, len(t), 4)), lambda o: o.replace("\x00", "").replace("?", "")


def multi_token_transforms():
    other = "ghp_" + body(36, 21)
    yield "multi-token", "two-plain", lambda t: t + " and " + other, None
    yield "multi-token", "adjacent", lambda t: other + t, None
    yield "multi-token", "plain-then-split-space", lambda t: other + " " + t[:prefix_len(t) + 20] + " " + t[prefix_len(t) + 20:], _drop(" ")
    yield "multi-token", "in-url-userinfo", lambda t: "https://x-access-token:" + t + "@github.com/o/r", None
    yield "multi-token", "json-escaped-quotes", lambda t: '{\\"token\\":\\"' + t + '\\"}', None
    yield "multi-token", "json-body", lambda t: '{"message":"Bad credentials","token":"' + t + '"}', None


def auth_separator_transforms():
    def only_auth(fn):
        def wrapped(token):
            n = prefix_len(token)
            if token[:n] not in ("Bearer ", "Basic ", "token "):
                return None
            return fn(token[:n - 1], token[n:])
        return wrapped
    yield "auth-separator", "equals", only_auth(lambda s, v: s + "=" + v), None
    yield "auth-separator", "colon", only_auth(lambda s, v: s + ":" + v), None
    yield "auth-separator", "colon-space", only_auth(lambda s, v: s + ": " + v), None
    yield "auth-separator", "json-key", only_auth(lambda s, v: '{"' + s.lower() + '":"' + v + '"}'), None
    yield "auth-separator", "header-plain", only_auth(lambda s, v: "Authorization: " + s + " " + v), None
    yield "auth-separator", "tab", only_auth(lambda s, v: s + "\t" + v), None
    yield "auth-separator", "pct20", only_auth(lambda s, v: s + "%20" + v), urllib.parse.unquote
    yield "auth-separator", "escaped-text-n", only_auth(lambda s, v: s + "\\n" + v), None
    yield "auth-separator", "nbsp", only_auth(lambda s, v: s + "\u00a0" + v), None


UNRECOGNISED = [
    ("aws-access-key", "AKIA" + "".join("ABCDEFGHJKLMNPQRSTUVWXYZ234567"[(2 + 3 * i) % 30] for i in range(16))),
    ("pem-block", "-----BEGIN PRIVATE KEY-----\n" + body(64, 8) + "\n-----END PRIVATE KEY-----"),
    ("hex64", "".join("0123456789abcdef"[(5 + 7 * i) % 16] for i in range(64))),
    ("jwt-alone", "eyJ" + body(17, 2) + "." + "eyJ" + body(40, 9) + "." + body(43, 4)),
    ("url-userinfo", "https://alice:" + body(24, 13) + "@example.invalid/path"),
    ("postgres-url", "postgres://app:" + body(24, 15) + "@db.invalid:5432/ai_memory"),
]


# ---------------------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------------------

def load(script):
    spec = importlib.util.spec_from_file_location("check_external_pr_approval_fuzz", str(script))
    if spec is None or spec.loader is None:
        raise SystemExit("cannot load " + str(script))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def relay(mod, stderr):
    """What ``gh_api`` relays for a failing ``gh`` whose stderr is ``stderr``."""
    def fake_run(*_a, **_k):
        return types.SimpleNamespace(returncode=1, stdout="", stderr=stderr)
    with unittest.mock.patch.object(mod.subprocess, "run", fake_run):
        _rc, lines = mod.run_gate("push", {}, "alphaonedev/ai-memory-mcp", "a" * 40, "alphaonedev", mod.gh_api)
    return "\n".join(lines)


def static_chunk_check(script):
    """No caller of redact() applies it per read chunk: cite the lines that prove it."""
    src = Path(script).read_text(encoding="utf-8").splitlines()
    facts = []
    for n, line in enumerate(src, 1):
        if "capture_output=True" in line or "redact(" in line or ".read(" in line or "splitlines" in line:
            facts.append("%s:%d: %s" % (Path(script).name, n, line.strip()))
    chunked = [f for f in facts if ".read(" in f]
    return facts, chunked


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--script", required=True, type=Path, help="path to check_external_pr_approval.py under test")
    ap.add_argument("--json", type=Path, help="write the per-case results here")
    ap.add_argument("--examples", type=int, default=3)
    ap.add_argument("--no-relay", action="store_true", help="skip the gh_api relay entry point (faster)")
    args = ap.parse_args()
    mod = load(args.script)

    tip = "?"
    try:
        tip = subprocess.run(["git", "-C", str(args.script.resolve().parent), "rev-parse", "HEAD"],
                             capture_output=True, text=True, check=False).stdout.strip() or "?"
    except OSError:
        pass

    results = {}  # class -> list of dict

    def record(cls, name, shape, carrier, secret, inverse):
        row = {"class": cls, "name": name, "shape": shape, "input": carrier, "len": len(carrier)}
        for entry in ("redact", "workflow_error", "relay"):
            if entry == "relay" and args.no_relay:
                continue
            if entry == "redact":
                out = mod.redact(carrier)
            elif entry == "workflow_error":
                out = mod.workflow_error(carrier)
            else:
                out = relay(mod, carrier + "\n")
            hit = leaked(secret, out, inverse)
            row[entry] = {"out": out, "leak": hit}
        results.setdefault(cls, []).append(row)

    for shape, token, secret in shapes():
        # (a) whole
        record("whole", "plain", shape, token, secret, None)
        record("whole", "in-sentence", shape, "HTTP 401 for " + token + " (end)", secret, None)
        # (b) split at every offset
        for cls, name, sep in split_transforms():
            for o in range(1, len(token)):
                record(cls, name + "@%d" % o, shape, token[:o] + sep + token[o:], secret, _drop(sep))
        # (c) prefix obfuscation + whole re-encodings
        for cls, name, fn, inverse in prefix_obfuscation_transforms():
            carrier = fn(token)
            if carrier is not None:
                record(cls, name, shape, carrier, secret, inverse)
        for cls, name, fn, inverse in whole_reencoding_transforms():
            record(cls, name, shape, fn(token), secret, inverse)
        # (d) multi-token lines, auth separators
        for cls, name, fn, inverse in multi_token_transforms():
            record(cls, name, shape, fn(token), secret, inverse)
        for cls, name, fn, inverse in auth_separator_transforms():
            carrier = fn(token)
            if carrier is not None:
                record(cls, name, shape, carrier, secret, inverse)
        # (e) per-chunk application (hypothetical: no 6117 caller chunks, see static check)
        for size in (4096, 8192):
            for straddle in (4, 12, 20):
                pad = "x" * (size - straddle)
                line = pad + token
                chunks = [line[i:i + size] for i in range(0, len(line), size)]
                out = "".join(mod.redact(c) for c in chunks)
                row = {"class": "chunk-boundary-hypothetical", "name": "chunk%d@%d" % (size, straddle), "shape": shape,
                       "input": "<%d x 'x'>%s" % (size - straddle, token), "len": len(line),
                       "redact": {"out": out[-120:], "leak": leaked(secret, out, None)}}
                results.setdefault("chunk-boundary-hypothetical", []).append(row)

    for name, text in UNRECOGNISED:
        secret = text
        for marker in ("-----BEGIN PRIVATE KEY-----\n", "https://alice:", "postgres://app:", "AKIA"):
            if text.startswith(marker):
                secret = text[len(marker):]
        secret = secret.split("@")[0].split("\n")[0]
        record("unrecognised-shape", name, name, text, secret, None)

    facts, chunked = static_chunk_check(args.script)

    # ---- report ----
    print("python: " + sys.version.split()[0] + "   script tip: " + tip)
    print("script: " + str(args.script))
    print()
    entries = ["redact", "workflow_error"] + ([] if args.no_relay else ["relay"])
    print("| class | total | " + " | ".join("bad(%s)" % e for e in entries) + " |")
    print("|---|---|" + "---|" * len(entries))
    grand = {"total": 0}
    for cls in results:
        rows = results[cls]
        counts = {e: sum(1 for r in rows if e in r and r[e]["leak"]) for e in entries}
        grand["total"] += len(rows)
        for e in entries:
            grand[e] = grand.get(e, 0) + counts[e]
        print("| %s | %d | %s |" % (cls, len(rows), " | ".join(str(counts[e]) for e in entries)))
    print("| **all** | %d | %s |" % (grand["total"], " | ".join(str(grand.get(e, 0)) for e in entries)))
    print()
    print("Minimal examples (shortest bad input per transform, one transform per line, the split placed right")
    print("after the prefix when that offset is bad; synthetic tokens; input/output are repr()):")
    for cls in results:
        bad = [r for r in results[cls] if any(e in r and r[e]["leak"] for e in entries)]
        if not bad:
            continue

        def rank(r):
            name, _at, off = r["name"].partition("@")
            worst = off.isdigit() and int(off) == 4 and r["shape"].startswith("gh")
            return (0 if worst else 1, r["len"], name)
        bad.sort(key=rank)
        picked = []
        seen = set()
        for r in bad:
            key = r["name"].partition("@")[0]
            if key in seen:
                continue
            seen.add(key)
            picked.append(r)
            if len(picked) >= args.examples:
                break
        print("\n### " + cls + "  (%d bad)" % len(bad))
        for r in picked:
            leaks = ", ".join("%s leaks %r" % (e, r[e]["leak"]) for e in entries if e in r and r[e]["leak"])
            print("- %s [%s]: in=%r" % (r["name"], r["shape"], r["input"][:90]))
            first = next(e for e in entries if e in r and r[e]["leak"])
            print("    out(%s)=%r" % (first, r[first]["out"][:120]))
            print("    " + leaks)
    print()
    print("Static chunk check (callers of redact and read paths in the script under test):")
    for f in facts:
        print("  " + f)
    print("  per-chunk read callers: %s" % (chunked if chunked else "none"))

    if args.json:
        args.json.write_text(json.dumps(results, indent=1, ensure_ascii=False), encoding="utf-8")
        print("json: " + str(args.json))
    return 0


if __name__ == "__main__":
    sys.exit(main())
