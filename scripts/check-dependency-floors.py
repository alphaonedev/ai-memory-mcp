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

Exit codes: 0 gate passes; 1 gate fails (unaccepted finding, expired or
malformed acceptance, OSV failure); 2 unusable input (lock file missing,
empty or not a Cargo.lock; non-https --osv-url).

Python 3.9+, standard library only.
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


class OsvError(Exception):
    """OSV could not be queried; the gate fails closed."""


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
    for aff in detail.get("affected", []):
        pkg = aff.get("package", {})
        if pkg.get("name") not in (None, name):
            continue
        if pkg.get("ecosystem") not in (None, ECOSYSTEM):
            continue
        if version in aff.get("versions", []):
            return "none"
        for rng in aff.get("ranges", []):
            if rng.get("type") == "GIT":
                continue
            events = sorted(rng.get("events", []), key=lambda e: vkey(next(iter(e.values()))))
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


def query_findings(packages, post, get, batch_size):
    """Return findings [{id, aliases, package, version, fixed_in}] from OSV."""
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
        if detail.get("withdrawn"):
            continue
        for n, v in hits[vid]:
            fixed = affected_fixed_in(detail, n, v)  # None: local walk cannot place the hit
            findings.append({"id": vid, "aliases": sorted(detail.get("aliases", [])),
                             "package": n, "version": v,
                             "fixed_in": UNKNOWN_FIX if fixed is None else fixed})
    return dedupe(findings)


def dedupe(findings):
    """Fold records that name the same advisory (id or alias overlap) into one."""
    out = []
    for f in sorted(findings, key=lambda x: (not x["id"].startswith("RUSTSEC"), x["id"])):
        ids = {f["id"]} | set(f["aliases"])
        for g in out:
            if g["package"] == f["package"] and g["version"] == f["version"] \
                    and ids & ({g["id"]} | set(g["aliases"])):
                g["aliases"] = sorted(set(g["aliases"]) | (ids - {g["id"]}))
                break
        else:
            out.append(f)
    return out


def merge_audit(findings, audit):
    """Merge a `cargo audit --json` document into findings by id or alias."""
    items = list(audit.get("vulnerabilities", {}).get("list", []))
    for group in audit.get("warnings", {}).values():
        items.extend(group)
    for item in items:
        adv, pkg = item.get("advisory"), item.get("package", {})
        if not adv:
            continue
        ids = {adv["id"]} | set(adv.get("aliases", []))
        patched = item.get("versions", {}).get("patched", [])
        known = [f for f in findings
                 if f["package"] == pkg.get("name") and ids & ({f["id"]} | set(f["aliases"]))]
        if known:
            known[0]["aliases"] = sorted(set(known[0]["aliases"]) | (ids - {known[0]["id"]}))
        else:
            findings.append({"id": adv["id"], "aliases": sorted(ids - {adv["id"]}),
                             "package": pkg.get("name", "?"), "version": pkg.get("version", "?"),
                             "fixed_in": ", ".join(patched) if patched else "none"})
    return dedupe(findings)


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


def evaluate(findings, entries, today):
    """Return (lines, problems, warnings, accepted_count, unaccepted_count)."""
    lines, problems, warnings = [], [], []
    used = set()
    n_acc = n_bad = 0
    for ent in entries:
        if ent["review_by"] < today:
            problems.append("acceptance %s (%s) expired on %s (tracking #%d)" % (
                ent["id"], ent["package"], ent["review_by"], ent["tracking_issue"]))
    for f in sorted(findings, key=lambda x: (x["id"], x["package"], x["version"])):
        ids = {f["id"]} | set(f["aliases"])
        match = None
        for idx, ent in enumerate(entries):
            if ent["package"] == f["package"] and ent["id"] in ids:
                match = ent
                used.add(idx)
                break
        if match is not None and match["review_by"] >= today:
            state = "yes via %s review_by=%s" % (match["id"], match["review_by"])
            n_acc += 1
        else:
            state = "no" if match is None else "expired %s via %s" % (match["review_by"], match["id"])
            n_bad += 1
        lines.append("floor: %s %s %s fixed_in=%s aliases=%s accepted=%s" % (
            f["id"], f["package"], f["version"], f["fixed_in"],
            ",".join(f["aliases"]) or "-", state))
    for idx, ent in enumerate(entries):
        if idx not in used:
            warnings.append("stale acceptance %s (%s): no locked version is affected, remove it" % (
                ent["id"], ent["package"]))
    return lines, problems, warnings, n_acc, n_bad


def build_io(args):
    base = args.osv_url.rstrip("/")
    if args.offline:
        saved = json.loads(Path(args.osv_json).read_text())
        hits, vulns = saved.get("hits", {}), saved.get("vulns", {})

        def post(path, body):
            res = []
            for q in body["queries"]:
                key = "%s@%s" % (q["package"]["name"], q["version"])
                res.append({"vulns": [{"id": i} for i in hits.get(key, [])]})
            return {"results": res}

        def get(path):
            return vulns[path[len(OSV_VULN_PATH):]]
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
    today = datetime.date.fromisoformat(args.today) if args.today else datetime.date.today()
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
    skipped = ["floor: skipped %s %s source=%s %s" % (
        n, v, k, "queried=yes" if k == KIND_PATH else "queried=no")
        for n, v, k in every if k != KIND_REGISTRY]
    packages = [(n, v) for n, v, k in every if k in (KIND_REGISTRY, KIND_PATH)]
    try:
        entries = parse_accepted(Path(args.accepted).read_text())
    except (OSError, AcceptedError) as exc:
        print("dependency-floors: acceptance file problem: %s" % exc, file=sys.stderr)
        return RC_FAIL
    post, get, record = build_io(args)
    try:
        findings = query_findings(sorted(set(packages)), post, get, args.batch_size)
    except OsvError as exc:
        print("dependency-floors: %s" % exc, file=sys.stderr)
        return RC_FAIL
    if record is not None and args.save_osv:
        Path(args.save_osv).write_text(json.dumps(record, indent=1, sort_keys=True))
    if args.audit_json:
        findings = merge_audit(findings, json.loads(Path(args.audit_json).read_text()))
    lines, problems, warnings, n_acc, n_bad = evaluate(findings, entries, today)
    for line in skipped + lines:
        print(line)
    for msg in warnings:
        print("warning: " + msg)
    for msg in problems:
        print("error: " + msg)
    print("dependency-floors: %d findings, %d accepted, %d unaccepted" % (len(findings), n_acc, n_bad))
    return RC_FAIL if (n_bad or problems) else RC_OK


if __name__ == "__main__":
    sys.exit(main())
