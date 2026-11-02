#!/usr/bin/env python3
"""OSV-backed dependency floor gate (#8473 item 5).

Reads Cargo.lock, asks OSV (https://api.osv.dev) which locked crates.io
versions fall in an affected range of a published advisory (RustSec and
GHSA-only records alike), optionally merges the local `cargo audit --json`
output, and compares every finding with the dated acceptances in
scripts/ci/dependency-floors-accepted.toml.

The OSV querybatch hit is authoritative: the local range walk only computes
the fixed version, and a hit it cannot place becomes a finding with
fixed_in=unknown, never a dropped one.

Every OSV record is evaluated on its own id: an acceptance covers a record
only when the acceptance id equals the record id or is one of that record's
own OSV aliases. Records that link directly id-to-alias fold into one display
group (one finding), but each keeps its own `floor:` line, fixed_in and
accepted state, and aliases never union across records.

Exit codes: 0 gate passes; 1 gate fails (unaccepted finding, expired or
malformed acceptance, OSV failure); 2 unusable input (lock file missing,
empty or not a Cargo.lock; non-https --osv-url; unparsable --today; a missing
or malformed --osv-json, --audit-json or OSV advisory shape).

Python 3.12+, standard library only.
"""
import argparse
import datetime
import json
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

OSV_BASE_URL = "https://api.osv.dev"
OSV_BATCH_PATH = "/v1/querybatch"
OSV_VULN_PATH = "/v1/vulns/"
ECOSYSTEM = "crates.io"
USER_AGENT = "ai-memory-dependency-floors/1 (+https://github.com/alphaonedev/ai-memory-mcp)"
MAX_BATCH = 1000
DEFAULT_RETRIES = 3
DEFAULT_BACKOFF_SECS = 1.0
HTTP_TIMEOUT_SECS = 60
MAX_RESPONSE_BYTES = 32 * 1024 * 1024
BATCH_RESULT_KEYS = ("vulns", "next_page_token")
BATCH_TOP_KEYS = ("results",)
REVIEW_BY_RE = re.compile(r"\d{4}-\d{2}-\d{2}")
LOCK_HEADER_RE = re.compile(r"^version = \d+\s*$")
KIND_REGISTRY = "registry"
KIND_GIT = "git"
KIND_PATH = "path"
KIND_OTHER = "other"
UNKNOWN_FIX = "unknown"
RC_OK = 0
RC_FAIL = 1
RC_INPUT = 2
ACCEPTED_REQUIRED = ("id", "package", "rationale", "review_by", "tracking_issue")
ACCEPTED_OPTIONAL = ("aliases",)
RFC3339_RE = re.compile(
    r"(\d{4}-\d{2}-\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(\.\d+)?([Zz]|[+-]\d{2}:\d{2})")


class OsvError(Exception):
    """OSV could not be queried; the gate fails closed."""


class InputError(Exception):
    """An input (offline OSV file, audit file, advisory shape, --today) is unusable; rc 2."""


class AcceptedError(Exception):
    """The acceptance file is malformed."""


def parse_lock_packages(text):
    """Return [(name, version, kind)] for every package of a Cargo.lock text.

    kind is registry, git, path (no source line: workspace members and vendored
    crates) or other.
    """
    packages = []
    cur = None
    for raw in text.splitlines():
        line = raw.strip()
        if line == "[[package]]":
            cur = {}
            packages.append(cur)
        elif line.startswith("["):
            cur = None
        elif cur is not None:
            m = re.match(r'^(\w+) = "(.*)"$', line)
            if m:
                cur[m.group(1)] = m.group(2)
    out = []
    for pkg in packages:
        if "name" not in pkg or "version" not in pkg:
            continue
        src = pkg.get("source")
        if src is None:
            kind = KIND_PATH
        elif src.startswith("registry+"):
            kind = KIND_REGISTRY
        elif src.startswith("git+"):
            kind = KIND_GIT
        else:
            kind = KIND_OTHER
        out.append((pkg["name"], pkg["version"], kind))
    return out


def parse_lock(text):
    """Return [(name, version)] for registry packages of a Cargo.lock text."""
    return [(n, v) for n, v, kind in parse_lock_packages(text) if kind == KIND_REGISTRY]


def has_lock_header(text):
    """True when the text carries the top-level `version = N` of a Cargo.lock."""
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("["):
            return False
        if LOCK_HEADER_RE.match(line):
            return True
    return False


def vkey(text):
    """Orderable semver key (semver 2.0.0 section 11); build metadata is ignored.

    A release sorts above every prerelease of the same core. Prerelease
    identifiers compare left to right: numeric ones numerically, alphanumeric
    ones lexically, numeric below alphanumeric, a shorter list below a longer
    one when all earlier identifiers are equal.
    """
    core = text.split("+", 1)[0]
    core, _, pre = core.partition("-")
    nums = []
    for part in core.split("."):
        nums.append(int(part) if part.isdigit() else 0)
    while len(nums) < 3:
        nums.append(0)
    if not pre:
        return (tuple(nums), (1,))
    ids = tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in pre.split("."))
    return (tuple(nums), (0, ids))


def affected_fixed_in(detail, name, version):
    """Return None when version is outside every affected range, else the fix text."""
    want = vkey(version)
    if not isinstance(detail, dict):
        raise InputError("OSV advisory detail is not an object")
    vid = detail.get("id", "?")

    def need(value, kind, what):
        if not isinstance(value, kind):
            raise OsvError("unparseable OSV record %s: %s is not a %s" % (
                vid, what, "list" if kind is list else "object"))
        return value

    for aff in need(detail.get("affected", []), list, "affected"):
        need(aff, dict, "an affected entry")
        pkg = need(aff.get("package", {}), dict, "package")
        if pkg.get("name") not in (None, name):
            continue
        if pkg.get("ecosystem") not in (None, ECOSYSTEM):
            continue
        if version in need(aff.get("versions", []), list, "versions"):
            return "none"
        for rng in need(aff.get("ranges", []), list, "ranges"):
            need(rng, dict, "a range entry")
            if rng.get("type") == "GIT":
                continue
            raw_events = need(rng.get("events", []), list, "events")
            for ev in raw_events:
                if not isinstance(ev, dict) or len(ev) != 1 or not isinstance(next(iter(ev.values())), str):
                    raise InputError("OSV advisory %s has a malformed range event: %r" % (
                        detail.get("id", "?"), ev))
            events = sorted(raw_events, key=lambda e: vkey(next(iter(e.values()))))
            start = None
            for ev in events:
                if "introduced" in ev:
                    start = vkey(ev["introduced"])
                elif start is not None and "fixed" in ev:
                    if start <= want < vkey(ev["fixed"]):
                        return ev["fixed"]
                    start = None
                elif start is not None and "last_affected" in ev:
                    if start <= want <= vkey(ev["last_affected"]):
                        return "none"
                    start = None
            if start is not None and start <= want:
                return "none"
    return None


class HttpsOnlyRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse any redirect whose target is not https (no downgrade)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not newurl.lower().startswith("https://"):
            raise OsvError("OSV redirect to a non-https URL refused: %s" % newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def http_json(url, payload, retries, backoff):
    """POST (payload given) or GET json with retries; raise OsvError when exhausted."""
    attempts = retries + 1
    last = None
    opener = urllib.request.build_opener(HttpsOnlyRedirect)
    for attempt in range(attempts):
        try:
            data = None if payload is None else json.dumps(payload).encode()
            req = urllib.request.Request(url, data=data, headers={
                "User-Agent": USER_AGENT, "Content-Type": "application/json"})
            with opener.open(req, timeout=HTTP_TIMEOUT_SECS) as resp:
                raw = resp.read(MAX_RESPONSE_BYTES + 1)
            if len(raw) > MAX_RESPONSE_BYTES:
                raise OsvError("OSV response from %s exceeds %d bytes" % (url, MAX_RESPONSE_BYTES))
            return json.loads(raw.decode())
        except OsvError:
            raise
        except Exception as exc:  # network, HTTP and decode errors all fail closed
            last = exc
            if attempt + 1 < attempts:
                time.sleep(backoff * (2 ** attempt))
    raise OsvError("OSV request to %s failed after %d attempts: %s" % (url, attempts, last))


def check_batch_response(reply, expected):
    """Return the results list of a querybatch reply; raise OsvError on any drift."""
    if not isinstance(reply, dict) or set(reply) - set(BATCH_TOP_KEYS):
        raise OsvError("OSV querybatch reply has an unexpected shape")
    results = reply.get("results")
    if not isinstance(results, list) or len(results) != expected:
        raise OsvError("OSV returned %s results for %d queries" % (
            len(results) if isinstance(results, list) else "no", expected))
    for res in results:
        if not isinstance(res, dict) or set(res) - set(BATCH_RESULT_KEYS):
            raise OsvError("OSV querybatch result has unexpected keys")
        if "next_page_token" in res:
            raise OsvError("OSV querybatch result is paginated (next_page_token); refusing a partial read")
        vulns = res.get("vulns", [])
        if not isinstance(vulns, list) or not all(isinstance(v, dict) and isinstance(v.get("id"), str)
                                                  for v in vulns):
            raise OsvError("OSV querybatch result carries a malformed vulns list")
    return results


def withdrawn_stamp(detail, vid, today=None):
    """Return the withdrawn timestamp text or None; a non-RFC-3339 value raises OsvError.

    A stamp dated after `today` is not withdrawn yet: the record stays live.
    """
    raw = detail.get("withdrawn")
    if raw is None:
        return None
    m = RFC3339_RE.fullmatch(raw) if isinstance(raw, str) else None
    ok = False
    if m is not None:
        try:
            datetime.date.fromisoformat(m.group(1))
            ok = int(m.group(2)) < 24 and int(m.group(3)) < 60 and int(m.group(4)) <= 60
        except ValueError:
            ok = False
    if not ok:
        raise OsvError("OSV advisory %s carries a withdrawn value that is not an RFC 3339 timestamp: %r" % (
            vid, raw))
    if today is not None and datetime.date.fromisoformat(m.group(1)) > today:
        return None
    return raw


def query_findings(packages, post, get, batch_size, notes=None, today=None):
    """Return one record {id, aliases, package, version, fixed_in} per OSV hit.

    Records are never merged here. A withdrawn advisory is skipped and
    announced as a `floor: withdrawn ...` line appended to notes.
    """
    hits = {}
    for i in range(0, len(packages), batch_size):
        chunk = packages[i:i + batch_size]
        body = {"queries": [{"package": {"name": n, "ecosystem": ECOSYSTEM}, "version": v}
                            for n, v in chunk]}
        results = check_batch_response(post(OSV_BATCH_PATH, body), len(chunk))
        for (n, v), res in zip(chunk, results):
            for vuln in res.get("vulns", []):
                hits.setdefault(vuln["id"], []).append((n, v))
    findings = []
    for vid in sorted(hits):
        detail = get(OSV_VULN_PATH + vid)
        if not isinstance(detail, dict):
            raise InputError("OSV advisory detail for %s is not an object" % vid)
        stamp = withdrawn_stamp(detail, vid, today)
        if stamp is not None:
            for n, v in hits[vid]:
                if notes is not None:
                    notes.append("floor: withdrawn %s %s %s withdrawn=%s" % (vid, n, v, stamp))
            continue
        aliases = detail.get("aliases") or []
        if not isinstance(aliases, list) or not all(isinstance(a, str) for a in aliases):
            raise InputError("OSV advisory %s has malformed aliases" % vid)
        for n, v in hits[vid]:
            fixed = affected_fixed_in(detail, n, v)  # None: local walk cannot place the hit
            findings.append({"id": vid, "aliases": sorted(aliases),
                             "package": n, "version": v,
                             "fixed_in": UNKNOWN_FIX if fixed is None else fixed})
    return findings


def linked(a, b):
    """True when two records link directly id-to-alias (either direction)."""
    return a["id"] in b["aliases"] or b["id"] in a["aliases"]


def group_findings(records):
    """Fold directly linked records into display groups: [[primary, folded...], ...].

    No transitive union: a folded record is never the anchor of another fold,
    and no record gains aliases. Each record is still evaluated on its own.
    """
    groups = []
    for rec in sorted(records, key=lambda x: (not x["id"].startswith("RUSTSEC"), x["id"],
                                              x["package"], x["version"])):
        for grp in groups:
            head = grp[0]
            if head["package"] == rec["package"] and head["version"] == rec["version"] \
                    and linked(head, rec):
                grp.append(rec)
                break
        else:
            groups.append([rec])
    return groups


def merge_audit(findings, audit):
    """Add `cargo audit --json` advisories that no OSV record already names.

    An advisory counts as already known only when a record with the same id,
    package and version exists. A linked but distinct advisory is appended, so
    it keeps its own aliases and fixed_in and is evaluated on its own;
    group_findings folds it for display only.
    """
    if not isinstance(audit, dict):
        raise InputError("cargo audit json is not an object")
    items = list((audit.get("vulnerabilities") or {}).get("list", []))
    for group in (audit.get("warnings") or {}).values():
        items.extend(group)
    out = list(findings)
    for item in items:
        if not isinstance(item, dict):
            raise InputError("cargo audit json has an entry that is not an object")
        adv, pkg = item.get("advisory"), item.get("package") or {}
        if not adv:
            continue
        if not isinstance(adv, dict) or not isinstance(adv.get("id"), str) or not adv["id"]:
            raise InputError("cargo audit json has an advisory without an id")
        raw_aliases = adv.get("aliases", [])
        if not isinstance(raw_aliases, list):
            raise InputError("cargo audit advisory %s has aliases that are not a list" % adv["id"])
        aliases = sorted(a for a in raw_aliases if isinstance(a, str))
        patched = item.get("versions", {}).get("patched", [])
        rec = {"id": adv["id"], "aliases": aliases, "package": pkg.get("name", "?"),
               "version": pkg.get("version", "?"),
               "fixed_in": ", ".join(patched) if patched else "none"}
        if any(f["id"] == rec["id"] and f["package"] == rec["package"]
               and f["version"] == rec["version"] for f in out):
            continue
        out.append(rec)
    return out


def parse_value(raw):
    raw = raw.strip()
    if re.fullmatch(r'"[^"\\]*"', raw):
        return raw[1:-1]
    if re.fullmatch(r"\d+", raw):
        return int(raw)
    if raw.startswith("[") and raw.endswith("]"):
        inner = raw[1:-1].strip()
        parts = [p.strip() for p in inner.split(",") if p.strip()]
        if not all(re.fullmatch(r'"[^"\\]*"', p) for p in parts):
            raise AcceptedError("unsupported array value: %s" % raw)
        return [p[1:-1] for p in parts]
    raise AcceptedError("unsupported value: %s" % raw)


def parse_accepted(text):
    """Parse the acceptance file into validated entries; raise AcceptedError."""
    entries, cur = [], None
    for num, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if line.startswith("#"):
            continue
        if not line:
            continue
        if line == "[[accepted]]":
            cur = {"_line": num}
            entries.append(cur)
            continue
        m = re.match(r"^(\w+)\s*=\s*(.+)$", line)
        if not m or cur is None:
            raise AcceptedError("line %d: unexpected content: %s" % (num, line))
        key = m.group(1)
        if key not in ACCEPTED_REQUIRED + ACCEPTED_OPTIONAL:
            raise AcceptedError("line %d: unknown key %s" % (num, key))
        cur[key] = parse_value(m.group(2))
    for ent in entries:
        where = "entry at line %d" % ent["_line"]
        for key in ACCEPTED_REQUIRED:
            if key not in ent:
                raise AcceptedError("%s: missing %s" % (where, key))
        for key in ("id", "package", "rationale"):
            if not isinstance(ent[key], str) or not ent[key].strip():
                raise AcceptedError("%s: %s must be a non-empty string" % (where, key))
        if not isinstance(ent["tracking_issue"], int) or ent["tracking_issue"] <= 0:
            raise AcceptedError("%s: tracking_issue must be a positive number" % where)
        if not isinstance(ent.get("aliases", []), list):
            raise AcceptedError("%s: aliases must be a list" % where)
        if not isinstance(ent["review_by"], str) or not REVIEW_BY_RE.fullmatch(ent["review_by"]):
            raise AcceptedError("%s: review_by must be a YYYY-MM-DD string" % where)
        try:
            ent["review_by"] = datetime.date.fromisoformat(ent["review_by"])
        except ValueError:
            raise AcceptedError("%s: review_by is not an ISO date" % where)
    seen = {}
    for ent in entries:
        key = (ent["id"], ent["package"])
        if key in seen:
            raise AcceptedError("entry at line %d duplicates the entry at line %d (%s, %s)" % (
                ent["_line"], seen[key], ent["id"], ent["package"]))
        seen[key] = ent["_line"]
    return entries


def covering(entries, rec):
    """Return (index, entry) of the first acceptance for this record on its own id/aliases."""
    for idx, ent in enumerate(entries):
        if ent["package"] == rec["package"] and (ent["id"] == rec["id"] or ent["id"] in rec["aliases"]):
            return idx, ent
    return None, None


def evaluate(groups, entries, today):
    """Return (lines, problems, warnings, accepted_groups, unaccepted_groups).

    One line per record. A group counts as accepted only when every record of
    it is covered by a live acceptance; any other group counts as unaccepted.
    """
    lines, problems, warnings = [], [], []
    used = set()
    n_acc = n_bad = 0
    for ent in entries:
        if ent["review_by"] < today:
            problems.append("acceptance %s (%s) expired on %s (tracking #%d)" % (
                ent["id"], ent["package"], ent["review_by"], ent["tracking_issue"]))
    for grp in sorted(groups, key=lambda g: (g[0]["id"], g[0]["package"], g[0]["version"])):
        group_ok = True
        for rec in grp:
            idx, match = covering(entries, rec)
            if match is not None:
                used.add(idx)
            if match is not None and match["review_by"] >= today:
                state = "yes via %s review_by=%s" % (match["id"], match["review_by"])
            else:
                group_ok = False
                state = "no" if match is None else "expired %s via %s" % (match["review_by"], match["id"])
            line = "floor: %s %s %s fixed_in=%s aliases=%s accepted=%s" % (
                rec["id"], rec["package"], rec["version"], rec["fixed_in"],
                ",".join(rec["aliases"]) or "-", state)
            if rec is not grp[0]:
                line += " folded_into=%s" % grp[0]["id"]
            lines.append(line)
        if group_ok:
            n_acc += 1
        else:
            n_bad += 1
    for idx, ent in enumerate(entries):
        if idx not in used:
            warnings.append("stale acceptance %s (%s): no locked version is affected, remove it" % (
                ent["id"], ent["package"]))
    return lines, problems, warnings, n_acc, n_bad


def manifest_package_name(path):
    """Return the [package] name of a Cargo.toml, or None when absent or unreadable."""
    try:
        text = Path(path).read_text()
    except OSError:
        return None
    in_pkg = False
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("["):
            in_pkg = line == "[package]"
        elif in_pkg:
            m = re.match(r'^name\s*=\s*"([^"]+)"', line)
            if m:
                return m.group(1)
    return None


def workspace_member_names(lock_path):
    """Names of the root and fuzz packages next to the lock (never queried by name)."""
    base = Path(lock_path).resolve().parent
    names = {manifest_package_name(base / "Cargo.toml"),
             manifest_package_name(base / "fuzz" / "Cargo.toml"),
             manifest_package_name(base.parent / "Cargo.toml") if base.name == "fuzz" else None}
    names.discard(None)
    return names


def build_io(args):
    base = args.osv_url.rstrip("/")
    if args.offline:
        try:
            saved = json.loads(Path(args.osv_json).read_text())
        except (OSError, ValueError) as exc:
            raise InputError("cannot read --osv-json %s: %s" % (args.osv_json, exc))
        if not isinstance(saved, dict):
            raise InputError("--osv-json %s is not an object" % args.osv_json)
        hits, vulns = saved.get("hits", {}), saved.get("vulns", {})

        def post(path, body):
            res = []
            for q in body["queries"]:
                key = "%s@%s" % (q["package"]["name"], q["version"])
                res.append({"vulns": [{"id": i} for i in hits.get(key, [])]})
            return {"results": res}

        def get(path):
            key = path[len(OSV_VULN_PATH):]
            if key not in vulns:
                raise InputError("--osv-json has no advisory %s" % key)
            return vulns[key]
        return post, get, None
    record = {"hits": {}, "vulns": {}}

    def post(path, body):
        out = http_json(base + path, body, args.retries, args.backoff)
        results = check_batch_response(out, len(body["queries"]))
        for q, res in zip(body["queries"], results):
            ids = [v["id"] for v in res.get("vulns", [])]
            if ids:
                record["hits"]["%s@%s" % (q["package"]["name"], q["version"])] = ids
        return out

    def get(path):
        out = http_json(base + path, None, args.retries, args.backoff)
        record["vulns"][path[len(OSV_VULN_PATH):]] = out
        return out
    return post, get, record


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--lock", default="Cargo.lock")
    ap.add_argument("--accepted", default="scripts/ci/dependency-floors-accepted.toml")
    ap.add_argument("--audit-json", help="cargo audit --json output to merge")
    ap.add_argument("--offline", action="store_true", help="use --osv-json instead of the network")
    ap.add_argument("--osv-json", help="saved OSV hits and advisories (offline test path)")
    ap.add_argument("--save-osv", help="write the live OSV responses to this file")
    ap.add_argument("--today", help="ISO date override for tests")
    ap.add_argument("--osv-url", default=OSV_BASE_URL)
    ap.add_argument("--retries", type=int, default=DEFAULT_RETRIES)
    ap.add_argument("--backoff", type=float, default=DEFAULT_BACKOFF_SECS)
    ap.add_argument("--batch-size", type=int, default=MAX_BATCH)
    args = ap.parse_args(argv)
    if args.offline and not args.osv_json:
        ap.error("--offline requires --osv-json")
    if not 1 <= args.batch_size <= MAX_BATCH:
        ap.error("--batch-size must be 1..%d" % MAX_BATCH)
    if not args.offline and not args.osv_url.lower().startswith("https://"):
        print("dependency-floors: --osv-url must be https:// unless --offline", file=sys.stderr)
        return RC_INPUT
    try:
        today = datetime.date.fromisoformat(args.today) if args.today else datetime.date.today()
    except ValueError:
        print("dependency-floors: --today %r is not a YYYY-MM-DD date" % args.today, file=sys.stderr)
        return RC_INPUT
    try:
        lock_text = Path(args.lock).read_text()
    except OSError as exc:
        print("dependency-floors: cannot read lock: %s" % exc, file=sys.stderr)
        return RC_INPUT
    every = parse_lock_packages(lock_text)
    if not has_lock_header(lock_text) or not any(k == KIND_REGISTRY for _, _, k in every):
        print("dependency-floors: %s is empty or not a Cargo.lock (no version header or no registry package)"
              % args.lock, file=sys.stderr)
        return RC_INPUT
    members = workspace_member_names(args.lock)

    def queried(n, k):
        return k == KIND_REGISTRY or (k == KIND_PATH and n not in members)
    skipped = ["floor: skipped %s %s source=%s %s" % (
        n, v, k, "queried=yes" if queried(n, k) else "queried=no")
        for n, v, k in every if k != KIND_REGISTRY]
    packages = [(n, v) for n, v, k in every if queried(n, k)]
    try:
        entries = parse_accepted(Path(args.accepted).read_text())
    except (OSError, AcceptedError) as exc:
        print("dependency-floors: acceptance file problem: %s" % exc, file=sys.stderr)
        return RC_FAIL
    notes = []
    try:
        post, get, record = build_io(args)
        findings = query_findings(sorted(set(packages)), post, get, args.batch_size, notes, today)
    except InputError as exc:
        print("dependency-floors: input problem: %s" % exc, file=sys.stderr)
        return RC_INPUT
    except OsvError as exc:
        print("dependency-floors: %s" % exc, file=sys.stderr)
        return RC_FAIL
    if record is not None and args.save_osv:
        Path(args.save_osv).write_text(json.dumps(record, indent=1, sort_keys=True))
    if args.audit_json:
        try:
            findings = merge_audit(findings, json.loads(Path(args.audit_json).read_text()))
        except (OSError, ValueError, InputError) as exc:
            print("dependency-floors: input problem: audit json %s: %s" % (args.audit_json, exc),
                  file=sys.stderr)
            return RC_INPUT
    groups = group_findings(findings)
    lines, problems, warnings, n_acc, n_bad = evaluate(groups, entries, today)
    for line in skipped + notes + lines:
        print(line)
    for msg in warnings:
        print("warning: " + msg)
    for msg in problems:
        print("error: " + msg)
    print("dependency-floors: %d findings, %d accepted, %d unaccepted" % (len(groups), n_acc, n_bad))
    return RC_FAIL if (n_bad or problems) else RC_OK


if __name__ == "__main__":
    sys.exit(main())
