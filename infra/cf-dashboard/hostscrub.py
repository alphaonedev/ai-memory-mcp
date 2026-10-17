"""Scrub internal node names and local paths out of anything published on the public dashboard (#7518).

Everything under infra/cf-dashboard/public/ is deployed to a public site. The state producers
(scripts/evidence/mcp-tools-state.py, push-state.py) call `dump_clean`, which replaces internal
hostnames and home / mount / scratch paths with fixed tokens and then REFUSES (LeakError) to hand back
text that still matches a leak pattern. The committed snapshots are checked with `find_leaks`.
"""
import json
import re

# built from parts so this source file does not itself contain the names it removes from the public pages
INTERNAL_HOSTNAMES = ("pop" + "-os", "FROSTY" + "i")
REDACTED = "node"
REDACTED_PATH = "<redacted-path>"

_PATH_TAIL = r"""[^\s"'\\,;)\]}]*"""
_PATH_PATTERNS = (
    r"(?:/home|/Users|/Volumes|/mnt|/root)/" + _PATH_TAIL,
    r"/ai-" + "scratch" + _PATH_TAIL,
    r"~/\.(?:env|ssh)" + _PATH_TAIL,
)
_PATH_RE = re.compile("|".join(_PATH_PATTERNS))


def _hostnames():
    return sorted({n.lower() for n in INTERNAL_HOSTNAMES}, key=len, reverse=True)


def _host_re():
    return re.compile(r"(?<![A-Za-z0-9])(?:%s)(?![A-Za-z0-9])" % "|".join(re.escape(n) for n in _hostnames()),
                      re.IGNORECASE)


def find_leaks(text):
    """Every internal hostname or local path left in `text` (an empty list means clean)."""
    return [m.group(0) for m in _host_re().finditer(text)] + [m.group(0) for m in _PATH_RE.finditer(text)]


def scrub_text(text):
    return _host_re().sub(REDACTED, _PATH_RE.sub(REDACTED_PATH, text))


def scrub(obj):
    """Return a copy of a JSON-shaped value with every string (keys included) scrubbed."""
    if isinstance(obj, str):
        return scrub_text(obj)
    if isinstance(obj, list):
        return [scrub(v) for v in obj]
    if isinstance(obj, dict):
        return {scrub_text(k) if isinstance(k, str) else k: scrub(v) for k, v in obj.items()}
    return obj


class LeakError(ValueError):
    """Scrubbed output still names an internal host or path; nothing may be written."""


def dump_clean(obj, **dumps_kwargs):
    """json.dumps of the scrubbed value; raises LeakError when anything leak-shaped survives."""
    text = json.dumps(scrub(obj), **dumps_kwargs)
    left = find_leaks(text)
    if left:
        raise LeakError("refusing to write: %d internal host/path match(es) survive scrubbing" % len(left))
    return text
