"""Scrub internal node names and local paths out of anything published on the public dashboard (#7518, #7547).

Everything under infra/cf-dashboard/public/ is deployed to a public site. The state producers
(scripts/evidence/mcp-tools-state.py, push-state.py) call `dump_clean`, which replaces internal
hostnames and home / mount / scratch paths with fixed tokens and then REFUSES (LeakError) to hand back
text that still matches a leak pattern. The committed snapshots are checked with `find_leaks`.

No internal hostname is committed here. Hosts are recognised by SHAPE (a positive rule): every
`host:<id>` and `ai:<id>@<host>` other than the public placeholder, and every name ending in a private DNS
suffix. On top of that the names in an UNTRACKED local file (one name per line, `#` comments; default
`hostnames.local` next to this module, or the path in CF_DASHBOARD_HOSTNAMES_FILE) are scrubbed. Nothing
depends on the hostname of the machine running the producer (#7592): the verdict and the output are the same
on every machine. A listed name matches as a whole host token (bounded by characters that cannot be part
of a host id), and so does a listed name followed by host-id suffix characters (`box-07`, `box_2`, `ai2`, #7641):
those derivatives are reported by find_leaks and scrubbed. Tokens that merely CONTAIN a listed name (`mailbox`,
`x-box`) are untouched, and the explicit exception list NAME_EXCEPTIONS (the product name `ai-memory`) is never
treated as a derivative. A configured names file that cannot be
read fails closed (LeakError); an unconfigured, absent default file is simply empty.
"""
import json
import os
import re
from pathlib import Path

REDACTED = "node"
REDACTED_PATH = "<redacted-path>"
NAMES_ENV = "CF_DASHBOARD_HOSTNAMES_FILE"
DEFAULT_NAMES_FILE = Path(__file__).resolve().parent / "hostnames.local"

# a derivative of a listed name that is NOT a host (#7641): tokens that start with one of these are left alone
NAME_EXCEPTIONS = ("ai-memory",)

_PATH_TAIL = r"""[^\s"'\\,;)\]}]*"""
_PATH_PATTERNS = (
    r"(?:/home|/Users|/Volumes|/mnt|/root)/" + _PATH_TAIL,
    r"/ai-" + "scratch" + _PATH_TAIL,
    r"~/\.(?:env|ssh)" + _PATH_TAIL,
)
_PATH_RE = re.compile("|".join(_PATH_PATTERNS))

_HOST_ID = r"[A-Za-z0-9](?:[A-Za-z0-9_-]|\.(?=[A-Za-z0-9]))*"
_NOT_PLACEHOLDER = r"(?!%s(?![A-Za-z0-9_-]))" % REDACTED
# host:<id> where <id> is not the public placeholder
_HOST_SHAPE_RE = re.compile(r"(?<![A-Za-z0-9])(host:)" + _NOT_PLACEHOLDER + _HOST_ID, re.IGNORECASE)
# ai:<agent>@<host> where <host> starts with a letter (so "@256" style text is untouched) and is not the placeholder
_AGENT_SHAPE_RE = re.compile(r"(?<![A-Za-z0-9])(ai:[A-Za-z0-9._-]+@)" + _NOT_PLACEHOLDER + r"[A-Za-z]" +
                             r"(?:[A-Za-z0-9_-]|\.(?=[A-Za-z0-9]))*", re.IGNORECASE)
# a private-DNS-suffixed name
_DNS_RE = re.compile(r"(?<![A-Za-z0-9.-])[A-Za-z0-9][A-Za-z0-9_-]*(?:\.[A-Za-z0-9_-]+)*\."
                     r"(?:local|lan|internal|home\.arpa|corp|localdomain|intranet)(?![A-Za-z0-9_-])", re.IGNORECASE)


class LeakError(ValueError):
    """Scrubbed output still names an internal host or path, or the names list could not be read; nothing may be written."""


def _names_from_file():
    configured = os.environ.get(NAMES_ENV)
    path = Path(configured) if configured else DEFAULT_NAMES_FILE
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        if configured:
            raise LeakError("the configured hostnames file is missing")
        return []
    except (OSError, UnicodeError):
        raise LeakError("the hostnames file cannot be read")
    names = []
    for line in raw.splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            names.append(line)
    return names


def configured_hostnames():
    """The names from the untracked local file (lower-cased, longest first); never the machine hostname."""
    return tuple(sorted({n.lower() for n in _names_from_file()}, key=len, reverse=True))


def __getattr__(name):
    if name == "INTERNAL_HOSTNAMES":
        return configured_hostnames()
    raise AttributeError(name)


def _name_re():
    names = configured_hostnames()
    if not names:
        return None
    # a whole host token: a listed name, optionally followed by [-_0-9] host characters (#7641). A name inside a
    # longer host id ("mailbox", "x-box") does not match: the lookbehind demands a token start.
    return re.compile(r"(?<![A-Za-z0-9_-])(?:%s)(?:[-_0-9][A-Za-z0-9_-]*)?(?![A-Za-z0-9_-])"
                      % "|".join(re.escape(n) for n in names), re.IGNORECASE)


def _name_hits(text):
    """Matches of the listed names (and their suffix derivatives), minus the NAME_EXCEPTIONS tokens."""
    name_re = _name_re()
    if name_re is None:
        return []
    return [m for m in name_re.finditer(text)
            if not m.group(0).lower().startswith(NAME_EXCEPTIONS)]


def find_leaks(text):
    """Every internal hostname or local path left in `text` (an empty list means clean)."""
    found = [m.group(0) for m in _HOST_SHAPE_RE.finditer(text)]
    found += [m.group(0) for m in _AGENT_SHAPE_RE.finditer(text)]
    found += [m.group(0) for m in _DNS_RE.finditer(text)]
    found += [m.group(0) for m in _name_hits(text)]
    return found + [m.group(0) for m in _PATH_RE.finditer(text)]


def scrub_text(text):
    text = _PATH_RE.sub(REDACTED_PATH, text)
    text = _HOST_SHAPE_RE.sub(lambda m: m.group(1) + REDACTED, text)
    text = _AGENT_SHAPE_RE.sub(lambda m: m.group(1) + REDACTED, text)
    text = _DNS_RE.sub(REDACTED, text)
    for m in reversed(_name_hits(text)):
        text = text[:m.start()] + REDACTED + text[m.end():]
    return text


def scrub(obj):
    """Return a copy of a JSON-shaped value with every string (keys included) scrubbed."""
    if isinstance(obj, str):
        return scrub_text(obj)
    if isinstance(obj, list):
        return [scrub(v) for v in obj]
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            key = scrub_text(k) if isinstance(k, str) else k
            if key in out:  # two keys scrubbed to one: the dict would silently drop a value (#7642)
                raise LeakError("refusing to write: two keys collapse to the same scrubbed key")
            out[key] = scrub(v)
        return out
    return obj


def dump_clean(obj, **dumps_kwargs):
    """json.dumps of the scrubbed value; raises LeakError when anything leak-shaped survives."""
    text = json.dumps(scrub(obj), **dumps_kwargs)
    left = find_leaks(text)
    if left:
        raise LeakError("refusing to write: %d internal host/path match(es) survive scrubbing" % len(left))
    return text
