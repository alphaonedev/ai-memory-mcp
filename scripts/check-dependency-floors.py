#!/usr/bin/env python3
"""OSV-backed dependency floor gate (#8473 item 5).

Reads Cargo.lock, asks OSV (https://api.osv.dev) which locked crates.io
versions fall in an affected range of a published advisory (RustSec and
GHSA-only records alike), optionally merges the local `cargo audit --json`
output, and compares every finding with the dated acceptances in
scripts/ci/dependency-floors-accepted.toml.

Exit codes: 0 gate passes; 1 gate fails (unaccepted finding, expired or
malformed acceptance, OSV failure); 2 unusable input (lock file missing).

Python 3.9+, standard library only.
"""
import argparse
import datetime
import json
import re
import sys
import time
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
RC_OK = 0
RC_FAIL = 1
RC_INPUT = 2
ACCEPTED_REQUIRED = ("id", "package", "rationale", "review_by", "tracking_issue")
ACCEPTED_OPTIONAL = ("aliases",)


class OsvError(Exception):
    """OSV could not be queried; the gate fails closed."""


class AcceptedError(Exception):
    """The acceptance file is malformed."""


def parse_lock(text):
    """Return [(name, version)] for registry packages of a Cargo.lock text."""
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
    return [(p["name"], p["version"]) for p in packages
            if "name" in p and "version" in p and p.get("source", "").startswith("registry+")]


def vkey(text):
    """Orderable key for a semver-ish version; a prerelease sorts below its release."""
    core = text.split("+", 1)[0]
    pre = "-" in core
    core = core.split("-", 1)[0]
    nums = []
    for part in core.split("."):
        nums.append(int(part) if part.isdigit() else 0)
    while len(nums) < 3:
        nums.append(0)
    return (tuple(nums), 0 if pre else 1)


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


def http_json(url, payload, retries, backoff):
    """POST (payload given) or GET json with retries; raise OsvError when exhausted."""
    attempts = retries + 1
    last = None
    for attempt in range(attempts):
        try:
            data = None if payload is None else json.dumps(payload).encode()
            req = urllib.request.Request(url, data=data, headers={
                "User-Agent": USER_AGENT, "Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_SECS) as resp:
                return json.loads(resp.read().decode())
        except Exception as exc:  # network, HTTP and decode errors all fail closed
            last = exc
            if attempt + 1 < attempts:
                time.sleep(backoff * (2 ** attempt))
    raise OsvError("OSV request to %s failed after %d attempts: %s" % (url, attempts, last))


def query_findings(packages, post, get, batch_size):
    """Return findings [{id, aliases, package, version, fixed_in}] from OSV."""
    hits = {}
    for i in range(0, len(packages), batch_size):
        chunk = packages[i:i + batch_size]
        body = {"queries": [{"package": {"name": n, "ecosystem": ECOSYSTEM}, "version": v}
                            for n, v in chunk]}
        results = post(OSV_BATCH_PATH, body).get("results", [])
        if len(results) != len(chunk):
            raise OsvError("OSV returned %d results for %d queries" % (len(results), len(chunk)))
        for (n, v), res in zip(chunk, results):
            for vuln in res.get("vulns", []):
                hits.setdefault(vuln["id"], []).append((n, v))
    findings = []
    for vid in sorted(hits):
        detail = get(OSV_VULN_PATH + vid)
        if detail.get("withdrawn"):
            continue
        for n, v in hits[vid]:
            fixed = affected_fixed_in(detail, n, v)
            if fixed is not None:
                findings.append({"id": vid, "aliases": sorted(detail.get("aliases", [])),
                                 "package": n, "version": v, "fixed_in": fixed})
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
        try:
            ent["review_by"] = datetime.date.fromisoformat(str(ent["review_by"]))
        except ValueError:
            raise AcceptedError("%s: review_by is not an ISO date" % where)
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
            if ent["package"] == f["package"] and ids & ({ent["id"]} | set(ent.get("aliases", []))):
                match = ent
                used.add(idx)
                break
        if match is not None and match["review_by"] >= today:
            state = "yes %s" % match["review_by"]
            n_acc += 1
        else:
            state = "no" if match is None else "expired %s" % match["review_by"]
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
        for q, res in zip(body["queries"], out.get("results", [])):
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
    today = datetime.date.fromisoformat(args.today) if args.today else datetime.date.today()
    try:
        packages = parse_lock(Path(args.lock).read_text())
    except OSError as exc:
        print("dependency-floors: cannot read lock: %s" % exc, file=sys.stderr)
        return RC_INPUT
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
    for line in lines:
        print(line)
    for msg in warnings:
        print("warning: " + msg)
    for msg in problems:
        print("error: " + msg)
    print("dependency-floors: %d findings, %d accepted, %d unaccepted" % (len(findings), n_acc, n_bad))
    return RC_FAIL if (n_bad or problems) else RC_OK


if __name__ == "__main__":
    sys.exit(main())
