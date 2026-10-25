#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Print bounded, redacted cert-bootstrap gate evidence into the job log (#7181).

``scripts/check-bootstrap-cert-gate.sh`` writes its LEG B evidence
(``bring-up.out`` and the refusal outputs) under the evidence directory. That
directory lives in the runner workspace, so when a LEG B row failed the reason
was lost with the runner. This helper prints the last ``--tail`` lines of each
evidence file under a ``--- <name> ---`` header, after redacting anything that
looks like key material or a credential, so the job log alone explains the red.

Modes: the default prints evidence; ``--write-redacted OUT`` writes a fully
redacted copy for the CI failure artifact; ``--finalize STATE`` is the gate's
EXIT trap (report LEG B evidence on a LEG B failure, then clean up).

Exit codes: 0 done, 2 usage or unreadable evidence directory (the offending
argument is never echoed).
"""
import argparse
import json
import re
import shutil
import sys
from pathlib import Path
from typing import IO, Any, Iterable, List

DEFAULT_TAIL_LINES = 200
REDACTED = "<redacted>"
DEFAULT_NAMES = (
    "bring-up.out",
    "refuse-no-keys.out",
    "refuse-unarmed.out",
    "witness-generate.out",
    "recorder-generate.out",
)
PEM_BEGIN = re.compile(r"-----BEGIN [A-Z0-9 ]*-----")
PEM_END = re.compile(r"-----END [A-Z0-9 ]*-----")
# Strong secret names (match as a substring of a longer key, any separator).
_STRONG_NAMES = (
    r"private[_ -]?key|secret|token|password|passwd|passphrase|pass[_ -]?phrase|seed|"
    r"api[_ -]?key|signing[_ -]?key|credentials?"
)
# Weak names are common words: match only as a whole word (or `_.-` delimited
# part of a key), and with a whitespace separator only when the value is 8+ chars.
_WEAK_NAMES = r"pass|pwd|auth|session|sessionid|session_id|cookie|csrf"
# A value is, in order: an escaped-quote value (backslash-quote ... backslash-quote, the
# Rust Debug / JSON-in-string shape), a double-quoted value, a single-quoted value, or a
# bare token. A quoted value whose closing quote is missing runs to the end of the line
# (the closer is optional).
_ESC_Q = r"\\*[\"']"
_VALUE = (
    r"(\\\"(?:[^\\]|\\(?!\"))*(?:\\\")?"
    r"|\"(?:[^\"\\]|\\.)*\"?"
    r"|'(?:[^'\\]|\\.)*'?"
    r"|\S+)"
)
# Shape 1 (strong name): ``k=v``, ``"k": "v"``, ``--passphrase v``, ``--passphrase=v``,
# ``secret key: v``, ``token v`` and list renders (``["--passphrase", "v"]``, Rust ``{:?}`` / repr); a quoted value runs to the closing UNESCAPED quote.
SECRET_KEY_VALUE = re.compile(
    r"(?i)(?<![a-z0-9])([a-z0-9_.-]*"
    r"(?:" + _STRONG_NAMES + r")"
    r"(?:[ _.-]?(?:key|b64|hex|value|id))?[a-z0-9_.-]*)"
    r"((?:" + _ESC_Q + r")\s*,\s*|(?:" + _ESC_Q + r")?(?:\s*[:=]\s*|\s+))" + _VALUE
)
# Shape 2 (weak name, ``:`` or ``=`` separator): ``session=v``, ``cookie: v``, ``AI_X_PASS=v``.
WEAK_KEY_VALUE = re.compile(
    r"(?i)(?<![a-z0-9])((?:[a-z0-9_.-]*[_.-])?(?:" + _WEAK_NAMES + r")(?:[_.-][a-z0-9_.-]*)?)(?![a-z0-9])"
    r"((?:" + _ESC_Q + r")?\s*[:=]\s*)" + _VALUE
)
# Shape 3 (weak name, whitespace separator): only a value of 8+ chars is masked.
WEAK_KEY_SPACE = re.compile(
    r"(?i)(?<![a-z0-9])((?:[a-z0-9_.-]*[_.-])?(?:" + _WEAK_NAMES + r")(?:[_.-][a-z0-9_.-]*)?)(?![a-z0-9])"
    r"((?:" + _ESC_Q + r")?\s+)(\S{8,})"
)
# Name test for a decoded JSON key (strong substring or weak whole word).
JSON_KEY_NAME = re.compile(
    r"(?i)(?:" + _STRONG_NAMES + r")|(?<![a-z0-9])(?:" + _WEAK_NAMES + r")(?![a-z0-9])"
)
# Shape 4: ``Authorization: <anything to end of line>`` and ``Bearer <tok>``.
AUTHORIZATION = re.compile(r"(?i)(authorization(?:" + _ESC_Q + r")?\s*[:=]\s*).*")
# Shape 4b: ``Cookie:`` / ``Set-Cookie:`` header, masked to the end of the line (every pair).
COOKIE_HEADER = re.compile(r"(?i)(?<![a-z0-9])((?:set-)?cookie2?(?:" + _ESC_Q + r")?\s*[:=]\s*).*")
BEARER = re.compile(r"(?i)\b(bearer\s+)\S+")
# Shape 5: well-known API token prefixes.
TOKEN_SHAPES = re.compile(r"\b(?:ghp_|gho_|ghs_|github_pat_|sk-)[A-Za-z0-9_\-]{8,}")
# Shape 6: URL userinfo, from ``://`` through the LAST ``@`` of the token (a raw
# ``@`` or ``/`` in the password stays inside the mask).
URL_CREDENTIALS = re.compile(r"(://)\S*@")
# Shape 7: 64+ hex chars (32-byte key or digest). Shape 8: base64 / base64url
# runs of 32+ chars (a 24-byte key encodes to 32), except an exact 40-hex git sha.
LONG_HEX = re.compile(r"(?<![0-9A-Za-z])[0-9a-fA-F]{64,}(?![0-9A-Za-z])")
LONG_B64 = re.compile(r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{32,}={0,2}")
GIT_SHA = re.compile(r"[0-9a-f]{40}")
# Shape 8b: an absolute path under a well-known filesystem root stays readable, in two
# passes. Pass 1 runs the 32+ floor over the WHOLE path before any ``/`` split: a 32+ run
# stays readable only when it is path-like (all of ``[a-z0-9._/-]``: no uppercase, no
# ``+``, no ``=``), so a std-base64 secret holding ``/`` is masked as one run. Pass 2 then
# checks every ``/`` segment on its own (a 32+ base64 run that is not exactly a 40-hex sha,
# or 64+ hex, is masked); a segment with an uppercase letter, ``+`` or ``=`` is joined with
# its neighbours. The root needs a boundary (``/run<token>`` is not a path). Any other slash
# run (URL path, bare ``a/b/c``) gets no exemption. ``KEY=/abs/path`` is a path too.
# macOS roots (#8174): ``Volumes``, ``Users`` and ``Library`` start uppercase, ``private`` does not.
# Only the ROOT segment may be uppercase: _mask_path peels it off before the lowercase-only
# passes, so a std-base64 secret under a root is still masked.
PATH_ROOTS = (
    "home|srv|usr|var|opt|mnt|etc|tmp|root|run|lib|bin|sbin|github|runner|workspace|ai-scratch"
    "|Volumes|Users|Library|private"
)
ROOT_BOUNDARY = r"(?=/|[^A-Za-z0-9+_=-]|$)"
SEG_LOWER = re.compile(r"[a-z0-9._-]*")
PATH_LIKE = re.compile(r"[a-z0-9._/-]*")
ABS_PATH = re.compile(
    r"(?<![A-Za-z0-9+/_.-])(/(?:" + PATH_ROOTS + r")" + ROOT_BOUNDARY + r"(?:/[A-Za-z0-9._+=-]*)*)"
)
PATH_SENTINEL = "\x00PATH%d\x00"
# Shape 9: ``\u00XX`` escapes that decode to a key-name character (alnum, ``_.- ``).
KEY_ESCAPE = re.compile(r"\\u([0-9a-fA-F]{4})")
# Public-key allowlist: a line starting with one of these keys keeps ONLY that
# field's value span; every other long run on the line is still masked.
PUBLIC_KEY_LINE = re.compile(
    r"(?i)^\s*[\"']?(?:pub_b64|pub_hex|pubkey|public_key|public_key_b64|public_key_hex)[\"']?\s*[:=]\s*"
)
# Only the key alphabet is exempt: a quoted or bare run of ``[A-Za-z0-9+/=_-]``, so
# ``pub_b64=<pk>;signing_key=<s>`` and ``pub_b64=<pk>,<s>`` keep only the public key.
PUBLIC_VALUE = re.compile(r"\"[A-Za-z0-9+/=_-]*\"|'[A-Za-z0-9+/=_-]*'|[A-Za-z0-9+/=_-]+")
PUBLIC_SENTINEL = "\x00PUBVAL\x00"
# Evidence files that may carry connection settings: never copied or uploaded.
EXCLUDED_PREFIXES = ("pg-posture-", "driverless-posture-")
USAGE_ERROR = "usage error (arguments not echoed)"


def _decode_key_escapes(line: str) -> str:
    """Decode ``\\uXXXX`` escapes that yield a key-name character so ``"p\\u0061ss"`` matches."""

    def sub(m: "re.Match") -> str:
        ch = chr(int(m.group(1), 16))
        return ch if (ch.isascii() and (ch.isalnum() or ch in "_.- ")) else m.group(0)

    return KEY_ESCAPE.sub(sub, line)


def _mask_json(node: Any) -> Any:
    """Mask every value (recursively) whose decoded key matches a secret name."""
    if isinstance(node, dict):
        return {k: (REDACTED if JSON_KEY_NAME.search(str(k)) else _mask_json(v)) for k, v in node.items()}
    if isinstance(node, list):
        return [_mask_json(v) for v in node]
    return node


def _try_json(text: str) -> Any:
    """Decoded object when ``text`` is a JSON object or array, else ``None``."""
    stripped = text.strip()
    if not stripped or stripped[0] not in "{[":
        return None
    try:
        return json.loads(stripped)
    except ValueError:
        return None


def _b64_sub(m: "re.Match") -> str:
    run = m.group(0)
    if GIT_SHA.fullmatch(run):
        return run
    return REDACTED


def _mask_segment(seg: str) -> str:
    """Mask one path segment: 64+ hex or a 32+ base64 run that is not an exact 40-hex sha."""
    return LONG_B64.sub(_b64_sub, LONG_HEX.sub(REDACTED, seg))


def _path_run_sub(m: "re.Match") -> str:
    run = m.group(0)
    if PATH_LIKE.fullmatch(run) or GIT_SHA.fullmatch(run):
        return run
    return REDACTED


def _mask_path(path: str) -> str:
    """Mask an absolute path: the whole-path floor first, then every segment on its own."""
    root, sep, rest = path[1:].partition("/")
    head = "/" + root
    if not sep:
        return head
    path = LONG_B64.sub(_path_run_sub, LONG_HEX.sub(REDACTED, sep + rest))
    segs = path.split("/")
    odd = [SEG_LOWER.fullmatch(s) is None for s in segs]
    n = len(segs)
    joined = [odd[i] or (i > 0 and odd[i - 1]) or (i + 1 < n and odd[i + 1]) for i in range(n)]
    out: List[str] = []
    i = 0
    while i < n:
        j = i + 1
        while joined[i] and j < n and joined[j]:
            j += 1
        out.append(_mask_segment("/".join(segs[i:j])))
        i = j
    return head + "/".join(out)


def _path_sub(found: List[str]):
    """Substitution that stashes a segment-checked absolute path behind a sentinel."""

    def sub(m: "re.Match") -> str:
        found.append(_mask_path(m.group(1)))
        return PATH_SENTINEL % (len(found) - 1)

    return sub


class Redactor:
    """Stateful redactor: ``in_pem`` survives line and chunk boundaries.

    Use ``feed_line`` per line or ``feed`` per arbitrary text chunk (a partial
    trailing line is carried to the next chunk; ``flush`` emits it).
    """

    def __init__(self) -> None:
        self.in_pem = False
        self._carry = ""

    def feed_line(self, line: str) -> str:
        """Return ``line`` with key material, secret values, tokens and credentials masked."""
        if self.in_pem:
            if PEM_END.search(line):
                self.in_pem = False
            return REDACTED
        if PEM_BEGIN.search(line):
            self.in_pem = not PEM_END.search(line)
            return REDACTED
        text = _decode_key_escapes(line)
        obj = _try_json(text)
        if obj is not None:
            text = json.dumps(_mask_json(obj), ensure_ascii=False)
        pub_value = None
        head = PUBLIC_KEY_LINE.match(text)
        if head:
            val = PUBLIC_VALUE.match(text, head.end())
            if val:
                pub_value = val.group(0)
                text = text[: val.start()] + PUBLIC_SENTINEL + text[val.end():]
        out = AUTHORIZATION.sub(lambda m: m.group(1) + REDACTED, text)
        out = COOKIE_HEADER.sub(lambda m: m.group(1) + REDACTED, out)
        out = BEARER.sub(lambda m: m.group(1) + REDACTED, out)
        out = SECRET_KEY_VALUE.sub(lambda m: m.group(1) + m.group(2) + REDACTED, out)
        out = WEAK_KEY_VALUE.sub(lambda m: m.group(1) + m.group(2) + REDACTED, out)
        out = WEAK_KEY_SPACE.sub(lambda m: m.group(1) + m.group(2) + REDACTED, out)
        out = TOKEN_SHAPES.sub(REDACTED, out)
        out = URL_CREDENTIALS.sub(lambda m: m.group(1) + REDACTED + "@", out)
        paths: List[str] = []
        out = ABS_PATH.sub(_path_sub(paths), out)
        out = LONG_HEX.sub(REDACTED, out)
        out = LONG_B64.sub(_b64_sub, out)
        for i, kept in enumerate(paths):
            out = out.replace(PATH_SENTINEL % i, kept)
        if pub_value is not None:
            out = out.replace(PUBLIC_SENTINEL, pub_value)
        return out

    def feed(self, chunk: str) -> List[str]:
        """Redact a text chunk of any size; returns the completed lines."""
        pieces = (self._carry + chunk).split("\n")
        self._carry = pieces.pop()
        return [self.feed_line(p) for p in pieces]

    def flush(self) -> List[str]:
        """Emit the carried partial line (if any)."""
        rest, self._carry = self._carry, ""
        return [self.feed_line(rest)] if rest else []


def redact_line(line: str) -> str:
    """Redact one standalone line (no PEM-block state)."""
    return Redactor().feed_line(line)


def redact_lines(lines: Iterable[str]) -> List[str]:
    """Redact a sequence of lines, masking whole PEM blocks."""
    red = Redactor()
    return [red.feed_line(x) for x in lines]


def redact_text(text: str) -> List[str]:
    """Redact a whole file: a JSON document is walked by decoded key first."""
    obj = _try_json(text) if "\n" in text.strip() else None
    if obj is not None:
        text = json.dumps(_mask_json(obj), ensure_ascii=False, indent=2)
    red = Redactor()
    return red.feed(text) + red.flush()


def evidence_names(evidence_dir: Path, names: Iterable[str]) -> List[str]:
    """The requested names followed by every other ``*.log`` / ``*.out`` file in the directory."""
    ordered = list(names)
    extra = sorted(
        p.name
        for p in evidence_dir.iterdir()
        if p.is_file() and p.suffix in (".log", ".out") and p.name not in ordered
    )
    return ordered + extra


def print_evidence(evidence_dir: Path, names: Iterable[str], tail_lines: int, stream: IO[str]) -> None:
    """Print the redacted last ``tail_lines`` lines of each named evidence file to ``stream``."""
    for name in names:
        path = Path(evidence_dir) / name
        stream.write("--- %s ---\n" % name)
        if not path.is_file():
            stream.write("(not present)\n")
            continue
        masked = redact_text(path.read_text(encoding="utf-8", errors="replace"))
        for line in masked[-tail_lines:] if tail_lines > 0 else []:
            stream.write(line + "\n")
    stream.flush()


def write_redacted(evidence_dir: Path, out_dir: Path) -> int:
    """Write a fully redacted copy of the evidence files to ``out_dir`` (replaced).

    Posture outputs are skipped. A missing evidence dir yields an empty copy.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    for old in out_dir.iterdir():
        if old.is_file():
            old.unlink()
    if not evidence_dir.is_dir():
        return 0
    for path in sorted(evidence_dir.iterdir()):
        if not path.is_file() or path.name.startswith(EXCLUDED_PREFIXES):
            continue
        masked = redact_text(path.read_text(encoding="utf-8", errors="replace"))
        (out_dir / path.name).write_text("\n".join(masked) + "\n", encoding="utf-8")
    return 0


def _safe_remove(raw: str) -> None:
    target = Path(raw)
    if not raw or not target.is_absolute() or target == Path(target.anchor):
        return
    if target.is_dir() and not target.is_symlink():
        shutil.rmtree(str(target), ignore_errors=True)
    elif target.exists() or target.is_symlink():
        target.unlink()


def _note_unavailable(stream: IO[str], exc: OSError) -> None:
    """Best-effort ``LEG B evidence unavailable`` line; a broken stream cannot raise (#7893)."""
    try:
        stream.write("\n== LEG B evidence unavailable: %s ==\n" % (exc.strerror or exc.__class__.__name__))
    except (OSError, ValueError):
        return  # the stream itself is gone: the trap must still keep the gate's exit status


def _stderr_note(text: str) -> None:
    """Best-effort stderr line for the EXIT trap: a closed stderr cannot raise (#7894)."""
    try:
        sys.stderr.write(text)
    except (OSError, ValueError):
        return


def finalize(state_dir: Path, evidence_dir: Path, tail_lines: int, stream: IO[str]) -> int:
    """EXIT-trap body of the gate: report LEG B evidence on a LEG B failure, then clean up.

    ``state_dir/fail-rows`` holds ``<phase><TAB><message>`` per failed row and
    ``state_dir/cleanup-list`` one absolute path per line. Never raises: the
    shell trap keeps the gate's own exit status.
    """
    rows = state_dir / "fail-rows"
    try:
        leg_b = rows.is_file() and any(
            ln.split("\t", 1)[0] == "B"
            for ln in rows.read_text(encoding="utf-8", errors="replace").splitlines()
        )
        if leg_b and evidence_dir.is_dir():
            stream.write("\n== LEG B evidence (redacted, last %d lines per file; #7181) ==\n" % tail_lines)
            print_evidence(evidence_dir, evidence_names(evidence_dir, DEFAULT_NAMES), tail_lines, stream)
    except OSError as exc:
        # The failure artifact must say its LEG B section is missing (#7893).
        _note_unavailable(stream, exc)
    listing = state_dir / "cleanup-list"
    try:
        paths = listing.read_text(encoding="utf-8", errors="replace").splitlines() if listing.is_file() else []
    except OSError:
        paths = []
    failed: List[str] = []
    for raw in paths:
        try:
            _safe_remove(raw.strip())
        except OSError:
            failed.append(raw.strip())
    if failed:  # residue on the runner must be detectable (#7894)
        _stderr_note("could not remove %d cleanup paths (first: %s)\n" % (len(failed), failed[0]))
    shutil.rmtree(str(state_dir), ignore_errors=True)
    return 0


class _QuietParser(argparse.ArgumentParser):
    def error(self, message: str):  # argparse hook: never echo the offending argument
        sys.stderr.write(USAGE_ERROR + "\n")
        raise SystemExit(2)


def main(argv: List[str]) -> int:
    parser = _QuietParser(description=__doc__.splitlines()[0])
    parser.add_argument("--evidence-dir", required=True, type=Path)
    parser.add_argument("--tail", type=int, default=DEFAULT_TAIL_LINES)
    parser.add_argument("--write-redacted", type=Path, default=None, metavar="OUT_DIR",
                        help="write a fully redacted copy of the evidence files to OUT_DIR")
    parser.add_argument("--finalize", type=Path, default=None, metavar="STATE_DIR",
                        help="gate EXIT trap: report LEG B evidence if a LEG B row failed, then clean up")
    parser.add_argument("names", nargs="*", help="evidence file names (default: the standard set)")
    args = parser.parse_args(argv)
    if args.finalize is not None:
        return finalize(args.finalize, args.evidence_dir, args.tail, sys.stdout)
    if args.write_redacted is not None:
        return write_redacted(args.evidence_dir, args.write_redacted)
    if not args.evidence_dir.is_dir():
        sys.stderr.write("evidence dir not found\n")
        return 2
    names = evidence_names(args.evidence_dir, args.names or DEFAULT_NAMES)
    print_evidence(args.evidence_dir, names, args.tail, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
