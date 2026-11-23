"""Certified data tier ratchet over the whole tracked tree (#9927, #9965-#9973).

Operator orders c4f4d408 and 111f59db (ai-memory, p10): the certified data
tier is ONE exact build: PostgreSQL 19.0 + Apache AGE 1.7.0 + pgvector 0.8.7.
Apache AGE 1.7.0 is built from upstream PG19 branch commit c6b043d plus
upstream fix commit 06ce678d (apache/age#2581, the IsTransactionState guard
of apache/age#2580); it is not a tagged Apache release. The tier base image
is pinned by digest.

The one source of truth is deploy/docker-1461/provision/lib.sh. This module
holds the invariant five ways:

* The SSOT itself carries every pin: the triple, the base image digest, the
  full AGE source commit, the upstream patch commit and the sha256 of the
  patch file and of the patched source file. The expected values are written
  out here by hand, never read from the code under test, and the patch file
  in the tree is checked against them.
* Every tracked file is scanned, history files included (a file that is not
  UTF-8 is decoded as latin-1 and scanned, and must be listed under
  "unreadable" in the allowlist with its reason). The rule fails closed by
  construction (#9951 r2): on a line that names the tier (a tier word, or a
  YAML parent key of the tier) EVERY numeric token must be a certified token
  derived from lib.sh (certified_tokens); any other token is
  `uncertified-token:<tok>`. The named forms are reported too: a stale-tier
  statement (PostgreSQL 18 in any spelling, Apache AGE 1.8.x, pgvector below
  0.8.7); a binding of a tier key to another version (shell default or
  assignment, typed constant, alias, YAML key or parent, quoted key in a
  dict, JSON object, tuple or match arm); an AGE commit sha other than the
  two pins; a postgres:19 image reference without the SSOT digest; a prefix
  glob or a non-exact grep over a tier version.
* The permitted sites are an ALLOWLIST of exact FULL lines, never whole
  files: scripts/ci/tests/data/certified_tier_allowlist.json maps a path to
  [line key, reason] entries (line_key: the sha256 of the stripped line, cut
  to 24 hex digits moved onto g..v), each entry waives ONE occurrence, and
  the reason is a code of ALLOW_REASONS. An entry that matches no finding
  line, an entry of an untracked path, a bad reason, a non-UTF-8 file not
  listed and a listed file that is UTF-8 are each a finding, so the list
  cannot rot. `python3 <this file> --print-missing` prints the regenerated
  allowlist (kept reasons, new lines with the reason of their path class).
* An AGE build is found by what a file EXECUTES (age_build_ledger.py:
  Dockerfile RUN, workflow `run:`, shell, Makefile recipe, Python
  subprocess argv), never by its text: every executed make of the AGE source
  must follow an executed run of the patch applier in the same unit.
* The consumers that build or assert the tier name the SSOT values, and the
  ledger finds exactly the AGE builders listed here, each one patched.
* The version assertions of the workflows are executed over a table of near
  misses (19.01, 1.7.00, 0.8.70 ...) and must refuse every one.
* The scanner is table-tested over every stale and drifted form and bounded
  in time on 100K-line inputs.

CERT_TIER_ROOT points the scan at another tree (an exported base or a
mutated copy) for the red-at-base and mutation proofs.
"""
import collections
import concurrent.futures
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import age_build_ledger  # noqa: E402

ROOT = Path(os.environ.get("CERT_TIER_ROOT") or Path(__file__).resolve().parents[3])
SSOT_PATH = "deploy/docker-1461/provision/lib.sh"
PATCH_DIR = "deploy/docker-1461/provision/patches"
APPLIER = age_build_ledger.APPLIER
ALLOWLIST_PATH = "scripts/ci/tests/data/certified_tier_allowlist.json"
# The whole-tree scan runs in a process pool once a tree has this many files;
# each file is one job, so the result equals the serial scan.
PARALLEL_MIN_FILES = 200
MAX_SCAN_WORKERS = 8
SCAN_CHUNK_FILES = 16

# Written by hand from operator orders c4f4d408 / 111f59db, the conductor's
# AGE source pin and the #9965 patch decision (independent of the code under
# test). The digest is the one postgres:19-trixie had at certification
# (#9969); the patch sha256 is of the repo file, the patched sha256 is of
# src/backend/catalog/ag_catalog.c after the patch on AGE_SOURCE_COMMIT.
BASE_DIGEST = "sha256:bb6e70add742cd868fb62cb3b2f67d1dd2bdd2b65a521e778420748753687c60"
EXPECTED_SSOT = {
    "PG_BASE_IMAGE": "postgres:19-trixie@" + BASE_DIGEST,
    "PG_MAJOR": "19",
    "PG_APT_VERSION": "19.0-2.pgdg13+1",
    "EXPECTED_PG_VERSION": "19.0",
    "EXPECTED_AGE_VERSION": "1.7.0",
    "AGE_SOURCE_REPO": "https://github.com/apache/age.git",
    "AGE_SOURCE_COMMIT": "c6b043d1c8f4909331b9080d6640b487782fc958",
    "AGE_PATCH_UPSTREAM_COMMIT": "06ce678d74210539705c77e2dc7c9fa861e2a331",
    "AGE_PATCH_FILE": "age-2580-06ce678d.patch",
    "AGE_PATCH_SHA256": "4d30cd91884756f281ec11dc5efd7ae2d32bcbeb9f90b44740dfec1fd2d25cc0",
    "AGE_PATCHED_FILE_SHA256": "3156a9b8ce13246fab82a07091303ad61a05981bdb3f88998b4e97bb778c640b",
}
EXPECTED_PGVECTOR_PREFIX = "0.8.7-"
SHORT_SHA_LEN = 7

# The exact wording every current doc and the changelog use for the AGE build.
AGE_PROVENANCE = (
    "Apache AGE 1.7.0, built from upstream PG19 branch commit c6b043d plus upstream fix commit "
    "06ce678d (apache/age#2581) (not a tagged Apache release; upstream has no 1.7.0 release for "
    "PostgreSQL 19)"
)

# --- stale-tier forms -------------------------------------------------------
SEP = r"[\s_:@/=*`'\"()-]{0,4}"
STALE_FORMS = {
    # pg18, PG 18, PostgreSQL 18.6, postgres:18, postgresql@18, release_PG18
    "postgres-18": re.compile(r"(?i)(?:postgres(?:ql)?|pg)" + SEP + r"v?18(?:\.\d+)?(?![0-9A-Za-z.])"),
    # postgresql-18, postgresql-server-dev-18, postgresql-client-18-...
    "postgres-pkg-18": re.compile(r"(?i)postgresql-(?:[a-z]+-){0,3}18(?![\w.])"),
    # Apache AGE 1.8.x in any spelling (AGE 1.8.0, AGE1.8.0, age-1.8.0, 1.8.0~rc0)
    "age-1.8": re.compile(r"(?i)\bage" + SEP + r"v?1\.8(?:\.\d+)?(?![\d])|1\.8\.0~rc\d"),
    # pgvector below the certified patch
    "pgvector-old": re.compile(r"(?i)(?:pgvector|pgv|vector)" + SEP + r"v?0\.8\.[0-6](?![\d])"),
    # SSOT variables removed when AGE became a pinned-commit source build
    "removed-ssot-var": re.compile(r"\bAGE_(?:APT_VERSION|BASE_IMAGE)\b"),
}
# A bare tier minor counts when the same line talks about the data tier. A
# bare 0.8.x counts only beside pgvector (sqlx-postgres is also 0.8.x). The
# tier words are identifier-aware: PG_MAJOR, DOCKER_1461_PG and AGE_VERSION
# name the tier although "_" is a word character (#9966).
TIER_WORD = re.compile(r"(?i)postgres|(?<![a-z])pg(?![a-z])|pgdg|pgvector|(?<![a-z])age(?![a-z])|apache age")
BARE_STALE = re.compile(r"(?<![\w.])(?:18\.\d+|1\.8\.\d+)(?![\d.]*[0-9A-Za-z%])")
VECTOR_WORD = re.compile(r"(?i)pgvector")
BARE_OLD_VECTOR = re.compile(r"(?<![\w.])0\.8\.[0-6](?![\d.]*[0-9A-Za-z%])")
# The tested alternate matrix (PG 16 + AGE 1.6.0 + pgvector 0.8.2 or 0.8.4)
# is not the certified tier: an old pgvector beside BOTH alternate members
# is the alternate, everywhere else it is a finding.
ALTERNATE = (re.compile(r"(?i)\bpg\W{0,2}16\b|postgresql\W{0,2}16\b"), re.compile(r"(?i)\bage\W{0,2}1\.6"))

# Tier variables: any default or assignment must equal the SSOT value.
TIER_VAR = re.compile(
    r"\b(?:DOCKER_1461_|DO_1461_|CERT_)?(PG_MAJOR|EXPECTED_PG_VERSION|EXPECTED_AGE_VERSION|"
    r"AGE_SOURCE_COMMIT|AGE_PATCH_UPSTREAM_COMMIT|AGE_PATCH_SHA256|AGE_PATCHED_FILE_SHA256)\b"
    r"(?:\}|\"|')?\s*(?::-|=|:\s)\s*[\"']?([0-9a-f][0-9a-f.]*)"
)
FULL_SHA = re.compile(r"(?i)(?:age[\w-]*commit|age_source|age@|apache/age[^\s]*?)[^0-9a-f]{0,40}\b([0-9a-f]{40})\b")
SHORT_SHA = re.compile(r"(?i)\bcommit\s+([0-9a-f]{7,40})\b")

# --- bindings of a tier key to a version, in every container form (#9966) ----
# key [quote] [: type] op [quote|(] value. The op covers shell (=, :-, :=),
# YAML/JSON (:), Rust/Python/TOML (=), match arms and Perl/Ruby hashes (=>),
# comparisons (==) and a quoted key in a tuple or array ("key", "value").
BINDING = re.compile(
    r"(?<![\w.$:/-])([A-Za-z][\w.-]{0,80})"
    r"(?:(['\"])\s*(?:,|:|=>)|\s*(?::\s*&?'?[A-Za-z][\w<>']{0,40}\s*)?(?::-|:=|=>|==|=|:))"
    r"\s*\(?\s*['\"]?v?(\d+(?:\.\d+){0,3}(?:-[\w.+~]+)?)(?![\w.])"
)
KEY_TOKEN = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|\d+")
KIND_TOKEN = re.compile(r"(pgvector|pgv|vector|age|postgresql|postgres|pg)(major|version|ver|num|release|minor)?")
VERSION_TOKENS = {"major", "version", "ver", "num", "release", "minor"}
DOTTED_VERSION = re.compile(r"\d+\.\d+(?:\.\d+)?(?:-[\w.+~]+)?")
YAML_PARENT = re.compile(r"^(\s*)-?\s*['\"]?([A-Za-z][\w.-]{0,80})['\"]?\s*:\s*(?:#.*)?$")


def certified_value(kind, value):
    """True when the value is the certified version of that component."""
    if kind == "pg":
        return value in {"19", "19.0", "190000"} or value.startswith("19.0-")
    if kind == "age":
        return value == "1.7.0"
    return value == "0.8.7" or value.startswith("0.8.7-")


# Words a tier pin's name may carry beside the component and the version word.
# A key with any other word (source_age_days, schema_version_postgres,
# AGE_VERSION_FLOOR, age_penalty) names something else and is not a pin.
NEUTRAL_TOKENS = {
    "expected", "docker", "do", "cert", "ci", "canonical", "certified", "server", "apt", "pkg", "ref", "tag",
    "image", "default", "pinned", "pin", "target", "required", "tier", "want", "build", "src", "ext", "extension",
    "lib", "dev",
}
KIND_NAME = {"pgv": "vector", "pgvector": "vector", "postgresql": "pg", "postgres": "pg"}
# PostgreSQL's own settings that report the server version carry no tier word.
PG_VERSION_SETTINGS = {"server_version", "server_version_num"}


def key_kind(key):
    """(kind, has a version token) of a key. kind is None when the key names no
    tier component, or names one beside a word that makes it something else."""
    if key.lower() in PG_VERSION_SETTINGS:
        return "pg", True
    kinds, versioned, bare_vector = set(), False, False
    for part in re.split(r"[_.-]", key):
        for tok in KEY_TOKEN.findall(part):
            tok = tok.lower()
            m = KIND_TOKEN.fullmatch(tok)
            if m:
                kind = KIND_NAME.get(m.group(1), m.group(1))
                kinds.add(kind)
                versioned = versioned or bool(m.group(2))
                bare_vector = bare_vector or (m.group(1) == "vector" and not m.group(2))
            elif tok in VERSION_TOKENS:
                versioned = True
            elif tok not in NEUTRAL_TOKENS and not tok.isdigit():
                return None, versioned
    if kinds == {"vector"} and bare_vector and not versioned:
        return None, versioned  # "vector = 0.7" is an embedding weight, not pgvector
    for kind in ("vector", "age", "pg"):
        if kind in kinds:
            return kind, versioned
    return None, versioned


# --- exact comparison (#9968) ------------------------------------------------
PREFIX_GLOB = re.compile(r"\$\{?([A-Za-z_]*(?:VERSION|MAJOR)[A-Za-z_]*)\}?\"?\*(?=[)\] \"])")
GREP_CALL = re.compile(r"\bgrep((?:\s+-[A-Za-z]+)*)\s+(['\"])([^'\"]{0,200})\2")
CERTIFIED_DOTTED = re.compile(r"(?<![\d.])(?:19\.0|1\.7\.0|0\.8\.7)(?![\d])|\$\{?\w*(?:PG|AGE|VECTOR)\w*(?:VERSION|MAJOR)")
TIER_VAR_NAME = re.compile(r"PG|AGE|VECTOR|POSTGRES")

# --- base image digest (#9969) -----------------------------------------------
BASE_REF = re.compile(r"(?<![\w-])postgres:19[\w.-]*(@sha256:[0-9a-f]{64})?")

# --- the allowlist ----------------------------------------------------------
HISTORY_PREFIXES = {
    "CHANGELOG.md": "released history; each section records the tier of its release",
    "changelog.d/3075.fixed.md": "fragment of an earlier change, history",
    "changelog.d/3552.security.md": "fragment of an earlier change, history",
    "changelog.d/6161.fixed.md": "fragment of an earlier change, history",
    "changelog.d/8224.changed.md": "fragment of the PG 18.6 move, history",
    "audits/": "dated audit campaign records",
    "docs/audit/": "dated audit records",
    "docs/reviews/": "dated review records and their evidence",
    "docs/handoff/": "dated handoff records",
    "docs/superpowers/handoff/": "dated handoff records",
    "docs/v0.7.0/": "v0.7.0 release and campaign records",
    "docs/v0.9.0/": "v0.9.0 epic and campaign records",
    "docs/v1.0.0/test-campaign-2026-08-08-enterprise-cert/": "dated campaign record",
    "docs/compliance/evidence/": "captured evidence of past certification runs",
    "docs/compliance/ENTERPRISE-FEDERATION-CERTIFICATION.md":
        "frozen certification record: check-cert-expiry holds it byte-identical while VOID or EXPIRED (#6124); "
        "the PG 19 tier enters it only through re-certification",
    "docs/release-v0.7.1.html": "v0.7.1 release page, history",
    "docs/whats-new-v063.html": "v0.6.3 release page, history",
    "docs/v070-changelog.html": "v0.7.0 changelog page, history",
    "docs/evidence/index.html": "index of captured evidence runs, history",
    "docs/bench/": "dated benchmark evidence",
    "migrations/postgres/0045_v88_list_composite_indexes.sql": "applied migrations are immutable",
    "scripts/ci/tests/test_certified_data_tier_pins.py": "this ratchet names the stale and drifted forms",
    "scripts/test/test_ensure_age_extension_6161.py":
        "tests of the helper's refusal of the stock 1.8.0 build and of its own F4 ratchet name the refused forms",
    "deploy/hive-1461/":
        "the v0.7.0 PG 16 federated baseline and the results it reproduces; it builds no v1.0.0 tier",
}
# A dated history note inside a current doc: the reason is mandatory, the
# region is capped so a current section cannot hide inside one, and only
# these files may hold one (#9966).
# The region marker word, split so this file itself carries no marker.
MARKER_PREFIX = "tier-" + "history"
HISTORY_BEGIN = re.compile(r"tier-history:\s*begin\b\s*(?:\(([^)]{8,})\))?")
HISTORY_END = re.compile(r"tier-history:\s*end\b")
MAX_HISTORY_REGION_LINES = 160
HISTORY_REGION_FILES = {
    "docs/DEV-CI-ENVIRONMENT.md": "dated f1/f2 node build notes",
    "docs/DEVELOPER_SETUP_NOTES.md": "dated f1 node build note",
    "docs/compliance/MISSION-CRITICAL-CERTIFICATION-STANDARD-v1.md": "dated certification history",
    "docs/kg-find-paths-engine.md": "dated benchmark note",
    "docs/reference-architecture/index.html": "dated hive run records",
    "docs/reproducible-baselines.html": "dated baseline run",
    "docs/testing/index.html": "dated test-run record",
    "docs/v1.0.0/release-notes.md": "dated release-history notes",
    "tests/kg_age_orphan_graph_3883.rs": "dated reproduction note of #3883",
}

# --- the token rule (#9951 r2): fail closed by construction ------------------
# A line names the tier when it carries one of these words. Bare "vector" is
# left out: every tier line that names pgvector says "pgvector", and the bare
# word is the Rust/SQL column type on thousands of lines that state no tier.
CONTEXT_RE = re.compile(r"(?i)postgres|(?<![a-z])pg(?![a-z])|server_version|(?<![a-z])age(?![a-z])|apache-age|pgvector")
# A numeric token: an ISO date (one token, so its day is never read as a
# major), a hex run of 7..64 digits (a sha or digest), or a dotted
# number with an optional packaging suffix (19.0-2.pgdg13+1). A digit glued to
# a letter, "_" or "." on its left (u32, sha256, x86_64) is not a token.
TOKEN_RE = re.compile(
    r"(?<![0-9A-Za-z])\d{4}-\d{2}-\d{2}(?![0-9A-Za-z])"
    r"|(?<![0-9A-Za-z])[0-9a-f]{7,64}(?![0-9A-Za-z])"
    r"|(?<![0-9A-Za-z_.])\d+(?:\.\d+)*(?:[-~+]\d[0-9A-Za-z]*(?:[.+~][0-9A-Za-z]*\d[0-9A-Za-z]*)*)?"
)
DIGIT_RE = re.compile(r"\d")
# The SSOT keys whose values are the certified tier.
CERTIFIED_KEYS = ("PG_MAJOR", "EXPECTED_PG_VERSION", "EXPECTED_AGE_VERSION", "PG_APT_VERSION",
                  "PGVECTOR_APT_VERSION", "AGE_PATCH_SHA256", "AGE_PATCHED_FILE_SHA256")
SHA_KEYS = ("AGE_SOURCE_COMMIT", "AGE_PATCH_UPSTREAM_COMMIT")
# Numbers that name the certified tier's own artefacts, not a version: the
# sha256 of a pin, the docker-1461 campaign of the SSOT, and the upstream AGE
# fix apache/age#2581 (its issue number 2580 comes from AGE_PATCH_FILE).
CERTIFIED_CONTEXT_NUMBERS = ("256", "1461", "2581")
PG_VERSION_NUM_FACTOR = 10000
ALLOW_REASONS = {
    "RECORD": "a dated record of an earlier tier: released changelog, review, audit, campaign record or immutable migration",
    "TEST": "a test fixture or expectation that plants or names another version on purpose",
    "CODE": "product code that names another version on purpose: a refused version, a version table or a ceiling note",
    "DOC": "documentation that names another number in context: the alternate matrix, a dated measurement or another component",
    "CONFIG": "configuration, tooling or CI text whose number is not the certified tier: a port, a count or another component",
}
LINE_KEY_LEN = 24
LINE_KEY_DIGITS = str.maketrans("0123456789abcdef", "ghijklmnopqrstuv")
LINE_KEY_RE = re.compile(rf"^[g-v]{{{LINE_KEY_LEN}}}$")


def certified_tokens(ssot):
    """Every numeric token a tier line may carry, derived from lib.sh."""
    cert = set(CERTIFIED_CONTEXT_NUMBERS)
    for key in CERTIFIED_KEYS:
        value = ssot.get(key, "")
        if value:
            cert.add(value)
            cert.add(value.split("-", 1)[0])
    major = ssot.get("PG_MAJOR", "")
    if major.isdigit():
        cert.add(str(int(major) * PG_VERSION_NUM_FACTOR))
    image = ssot.get("PG_BASE_IMAGE", "")
    if "@sha256:" in image:
        cert.add(image.rsplit(":", 1)[-1])
    issue = re.fullmatch(r"age-(\d+)-[0-9a-f]{7,40}\.patch", ssot.get("AGE_PATCH_FILE", ""))
    if issue:
        cert.add(issue.group(1))
    for key in SHA_KEYS:
        sha = ssot.get(key, "").lower()
        if re.fullmatch(r"[0-9a-f]{40}", sha):
            cert.update(sha[:n] for n in range(SHORT_SHA_LEN, len(sha) + 1))
    return frozenset(cert - {""})


def token_findings(line, cert):
    """`uncertified-token:<tok>` for each distinct numeric token of a tier line."""
    out, seen = [], set()
    for m in TOKEN_RE.finditer(line):
        tok = m.group(0)
        if tok not in seen and tok not in cert and DIGIT_RE.search(tok):
            out.append(f"uncertified-token:{tok}")
        seen.add(tok)
    return out


def line_key(line):
    """The allowlist key of one full stripped line: sha256 cut to 24 hex
    digits, each moved onto g..v so the allowlist itself holds no digit."""
    return hashlib.sha256(line.encode("utf-8")).hexdigest()[:LINE_KEY_LEN].translate(LINE_KEY_DIGITS)


def load_allowlist(root=ROOT):
    return json.loads((root / ALLOWLIST_PATH).read_text(encoding="utf-8"))


def allow_counters(allowlist):
    """{path: (good Counter, bad Counter)} and the findings of malformed entries."""
    lines = allowlist.get("lines") if isinstance(allowlist, dict) else None
    problems = []
    if not isinstance(allowlist, dict) or set(allowlist) != {"lines", "unreadable"} or not isinstance(lines, dict) \
            or not isinstance(allowlist.get("unreadable"), dict):
        return {}, [f"{ALLOWLIST_PATH}: allowlist-malformed"]
    out = {}
    for rel, entries in lines.items():
        good, bad = collections.Counter(), collections.Counter()
        if not isinstance(entries, list):
            problems.append(f"{rel}: allowlist-entry-malformed")
            continue
        for entry in entries:
            if not (isinstance(entry, list) and len(entry) == 2 and isinstance(entry[0], str)
                    and LINE_KEY_RE.match(entry[0])):
                problems.append(f"{rel}: allowlist-entry-malformed")
                continue
            (good if entry[1] in ALLOW_REASONS else bad)[entry[0]] += 1
        out[rel] = (good, bad)
    for rel, why in allowlist["unreadable"].items():
        if not (isinstance(why, str) and why.strip()):
            problems.append(f"{rel}: unreadable-entry-without-reason")
    return out, problems


def path_reason(rel):
    """The reason code --print-missing gives a new line of this path."""
    name = rel.rsplit("/", 1)[-1]
    if history_reason(rel):
        return "RECORD"
    if rel.startswith(("tests/", "scripts/test/", "scripts/ci/tests/")) or "/tests/" in rel or name.startswith("test_") \
            or "_test." in name or "_tests." in name:
        return "TEST"
    if rel.startswith("src/"):
        return "CODE"
    if rel.startswith(("docs/", "changelog.d/")) or name.endswith((".md", ".html")) or name.startswith("CHANGELOG"):
        return "DOC"
    return "CONFIG"


def tracked_files(root):
    if (root / ".git").exists():
        out = subprocess.run(["git", "-C", str(root), "ls-files", "-z"], capture_output=True, check=True).stdout
        return sorted(p.decode() for p in out.split(b"\0") if p)
    return sorted(str(p.relative_to(root)) for p in root.rglob("*") if p.is_file())


def read_file(root, rel):
    """(text, is_utf8). A file that is not UTF-8 is decoded as latin-1, so no byte is skipped."""
    data = (root / rel).read_bytes()
    try:
        return data.decode("utf-8"), True
    except UnicodeDecodeError:
        return data.decode("latin-1"), False


def read_text(root, rel):
    try:
        return read_file(root, rel)[0]
    except OSError:
        return None


def parse_ssot(text):
    """Shell defaults `VAR="${DOCKER_1461_VAR:-value}"` from the SSOT."""
    found = {}
    for m in re.finditer(r'^([A-Z_0-9]+)="\$\{DOCKER_1461_\1:-([^}]*)\}"', text, re.M):
        found[m.group(1)] = m.group(2)
    return found


def history_reason(rel):
    for prefix, reason in HISTORY_PREFIXES.items():
        if rel == prefix or (prefix.endswith("/") and rel.startswith(prefix)):
            return reason
    return None


def allowed_shas(ssot):
    return {ssot.get("AGE_SOURCE_COMMIT", ""), ssot.get("AGE_PATCH_UPSTREAM_COMMIT", "")} - {""}


def binding_findings(line, parent_kind, skip_spans):
    reasons = []
    for m in BINDING.finditer(line):
        if any(a < m.end() and m.start() < b for a, b in skip_spans):
            continue
        key, value = m.group(1), m.group(3)
        kind, versioned = key_kind(key)
        if kind is None and parent_kind and versioned:
            kind = parent_kind
        if kind is None or not (versioned or DOTTED_VERSION.fullmatch(value)):
            continue
        if re.fullmatch(r"\d{7,}", value) or certified_value(kind, value):
            continue
        reasons.append(f"{kind}-binding:{key}={value}")
    return reasons


def compare_findings(line):
    reasons = []
    for m in PREFIX_GLOB.finditer(line):
        if TIER_VAR_NAME.search(m.group(1)):
            reasons.append(f"version-prefix-glob:{m.group(1)}")
    for m in GREP_CALL.finditer(line):
        flags = "".join(f.strip().lstrip("-") for f in m.group(1).split())
        if CERTIFIED_DOTTED.search(m.group(3)) and not ("x" in flags and "F" in flags):
            reasons.append("version-grep-inexact")
    return reasons


def digest_findings(line, ssot):
    want = "@" + ssot.get("PG_BASE_IMAGE", "@").split("@", 1)[-1]
    reasons = []
    for m in BASE_REF.finditer(line):
        if m.group(1) != want:
            reasons.append("base-image-not-digest-pinned" if not m.group(1) else "base-image-digest-differs")
    return reasons


def line_findings(line, ssot, parent_kind=None):
    """Every stale-tier reason the one line carries (empty when clean)."""
    alternate = all(rx.search(line) for rx in ALTERNATE)
    reasons = [name for name, rx in STALE_FORMS.items() if rx.search(line) and not (alternate and name == "pgvector-old")]
    if not reasons and TIER_WORD.search(line) and BARE_STALE.search(line):
        reasons.append("bare-stale-version")
    if not reasons and not alternate and VECTOR_WORD.search(line) and BARE_OLD_VECTOR.search(line):
        reasons.append("bare-stale-pgvector")
    spans = []
    for m in TIER_VAR.finditer(line):
        spans.append(m.span())
        var, value = m.group(1), m.group(2)
        want = ssot.get(var)
        if want is not None and value != want:
            reasons.append(f"{var}={value}")
    shas = allowed_shas(ssot)
    for m in FULL_SHA.finditer(line):
        if m.group(1).lower() not in shas:
            reasons.append(f"age-sha={m.group(1)}")
    if "PG19" in line or "AGE 1.7.0" in line or "age_source" in line.lower():
        for m in SHORT_SHA.finditer(line):
            if not any(s.startswith(m.group(1).lower()) for s in shas):
                reasons.append(f"age-short-sha={m.group(1)}")
    if not alternate:
        reasons += binding_findings(line, parent_kind, spans)
    reasons += compare_findings(line)
    reasons += digest_findings(line, ssot)
    return reasons


def line_reasons(line, ssot, parent_kind, cert):
    """The named-form reasons of a line, then each uncertified token of a
    line that names the tier (a tier word, or a YAML parent of the tier)."""
    reasons = line_findings(line, ssot, parent_kind)
    if parent_kind or CONTEXT_RE.search(line):
        reasons += [r for r in token_findings(line, cert) if r not in reasons]
    return reasons


def scan_text(rel, text, ssot, region_files=HISTORY_REGION_FILES, allow=None, missing=None):
    """Findings of one file. A dated history note inside a current doc sits in
    a region between a begin marker with a reason and an end marker (the
    HISTORY_BEGIN and HISTORY_END forms); the region is skipped. This module
    builds its markers from MARKER_PREFIX, so its own text holds none. A region in a file not in region_files, a begin
    without a reason, a nested begin, an end without a begin, an unclosed
    region, a region over the size cap and a region that holds no stale
    statement are each a finding. A YAML key without a tier word of its own
    takes the tier of the nearest enclosing parent key. `allow` is the
    file's (good, bad) Counter pair of line keys: each entry waives one
    finding line and is consumed; a bad-reason entry waives the line but is
    a finding itself. `missing` collects the stripped finding lines left."""
    findings, used_lines = [], set()
    cert = certified_tokens(ssot)
    good, bad = allow if allow is not None else (collections.Counter(), collections.Counter())
    region = None  # (start line, stale lines seen)
    parents = []  # (indent, kind)
    for n, line in enumerate(text.splitlines(), 1):
        begin, end = HISTORY_BEGIN.search(line), HISTORY_END.search(line)
        if begin:
            if rel not in region_files:
                findings.append(f"{rel}:{n}: history-region-in-unlisted-file")
            if region is not None:
                findings.append(f"{rel}:{n}: history-region-nested")
            elif not begin.group(1):
                findings.append(f"{rel}:{n}: history-region-no-reason")
            region = (n, 0)
            continue
        if end:
            if region is None:
                findings.append(f"{rel}:{n}: history-region-end-without-begin")
            elif region[1] == 0:
                findings.append(f"{rel}:{region[0]}: history-region-holds-no-stale-statement")
            elif n - region[0] > MAX_HISTORY_REGION_LINES:
                findings.append(f"{rel}:{region[0]}: history-region-over-{MAX_HISTORY_REGION_LINES}-lines")
            region = None
            continue
        if line.strip():
            indent = len(line) - len(line.lstrip())
            while parents and parents[-1][0] >= indent:
                parents.pop()
        parent_kind = next((k for _, k in reversed(parents) if k), None)
        y = YAML_PARENT.match(line)
        if y:
            parents.append((len(y.group(1)), key_kind(y.group(2))[0]))
        reasons = line_reasons(line, ssot, parent_kind, cert)
        if not reasons:
            continue
        if region is not None:
            region = (region[0], region[1] + 1)
            continue
        stripped = line.strip()
        key = line_key(stripped)
        if good[key] > 0:
            good[key] -= 1
            used_lines.add((rel, key))
            continue
        if bad[key] > 0:
            bad[key] -= 1
            findings.append(f"{rel}: allowlist-entry-bad-reason:{key}")
            continue
        if missing is not None:
            missing.append((rel, stripped))
        findings.append(f"{rel}:{n}: {','.join(reasons)}: {stripped[:160]}")
    if region is not None:
        findings.append(f"{rel}:{region[0]}: history-region-unclosed")
    return findings, used_lines


def dead_entries(rel, good, bad):
    return [f"{rel}: dead-allowlist-entry:{key}" for counter in (good, bad)
            for key in sorted(counter) for _ in range(counter[key])]


def scan_file(job):
    """The findings of one tracked file: (findings, used line keys, missing lines).
    One file is one unit of work, so its allowlist counters never cross files
    and the result is the same run serially or in a process pool."""
    root, rel, ssot, (good, bad), listed_unreadable, want_missing = job
    root = Path(root)
    findings, lost = [], [] if want_missing else None
    try:
        text, utf8 = read_file(root, rel)
    except OSError as exc:
        return [f"{rel}: unreadable ({type(exc).__name__})"], set(), lost or []
    if utf8 and listed_unreadable:
        findings.append(f"{rel}: unreadable-entry-is-utf8")
    if not utf8 and not listed_unreadable:
        findings.append(f"{rel}: non-utf8-unlisted")
    found, used = scan_text(rel, text, ssot, allow=(good, bad), missing=lost)
    findings.extend(found)
    if utf8:
        findings.extend(age_build_ledger.findings(rel, text, ssot))
    findings.extend(dead_entries(rel, good, bad))
    return findings, used, lost or []


def scan(root, ssot, allowlist=None, missing=None):
    """Every finding of the tree, in file order, then the dead entries of
    paths that are not tracked. A tracked file that is not UTF-8 must be
    listed under "unreadable"; a listed one that is UTF-8 is a finding; it is
    scanned either way. The AGE build ledger runs on every file."""
    if allowlist is None:
        allowlist = load_allowlist(root)
    counters, findings = allow_counters(allowlist)
    unreadable = allowlist.get("unreadable", {}) if isinstance(allowlist, dict) else {}
    used_lines = set()
    files = tracked_files(root)
    jobs = [(str(root), rel, ssot, counters.get(rel, (collections.Counter(), collections.Counter())),
             rel in unreadable, missing is not None) for rel in files]
    if len(jobs) >= PARALLEL_MIN_FILES and (os.cpu_count() or 1) > 1:
        workers = min(MAX_SCAN_WORKERS, os.cpu_count() or 1)
        with concurrent.futures.ProcessPoolExecutor(max_workers=workers) as pool:
            results = list(pool.map(scan_file, jobs, chunksize=SCAN_CHUNK_FILES))
    else:
        results = [scan_file(job) for job in jobs]
    for found, used, lost in results:
        findings.extend(found)
        used_lines.update(used)
        if missing is not None:
            missing.extend(lost)
    tracked = set(files)
    for rel in sorted(set(counters) - tracked):
        findings.extend(dead_entries(rel, *counters[rel]))
    for rel in sorted(set(unreadable) - tracked):
        findings.append(f"{rel}: dead-unreadable-entry")
    return findings, used_lines


def ssot_now():
    return parse_ssot(read_text(ROOT, SSOT_PATH) or "")


class SsotTest(unittest.TestCase):
    def test_ssot_carries_the_certified_triple_and_age_sha_9927(self):
        ssot = ssot_now()
        for var, want in EXPECTED_SSOT.items():
            self.assertEqual(ssot.get(var), want, f"{SSOT_PATH} {var}")
        self.assertTrue(ssot.get("PGVECTOR_APT_VERSION", "").startswith(EXPECTED_PGVECTOR_PREFIX), ssot)
        self.assertNotIn("AGE_APT_VERSION", ssot, "AGE is a pinned-commit source build, not an apt package")

    def test_base_image_is_pinned_by_digest_9969(self):
        image = ssot_now().get("PG_BASE_IMAGE", "")
        self.assertRegex(image, r"^postgres:19-trixie@sha256:[0-9a-f]{64}$")
        self.assertEqual(image, EXPECTED_SSOT["PG_BASE_IMAGE"])

    def test_patch_file_matches_its_pins_9965(self):
        ssot = ssot_now()
        path = ROOT / PATCH_DIR / EXPECTED_SSOT["AGE_PATCH_FILE"]
        data = path.read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(), EXPECTED_SSOT["AGE_PATCH_SHA256"], path)
        self.assertEqual(ssot.get("AGE_PATCH_SHA256"), hashlib.sha256(data).hexdigest())
        text = data.decode("utf-8")
        self.assertEqual(text.splitlines()[0], f"From {EXPECTED_SSOT['AGE_PATCH_UPSTREAM_COMMIT']} Mon Sep 17 00:00:00 2001")
        added = [line[1:].strip() for line in text.splitlines() if line.startswith("+") and not line.startswith("+++")]
        self.assertIn("if (!IsTransactionState())", added)
        self.assertIn("return false;", added)
        touched = [line for line in text.splitlines() if line.startswith("+++ ")]
        self.assertEqual(touched, ["+++ b/src/backend/catalog/ag_catalog.c"], "the patch touches exactly the one file")


class WholeTreeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ssot = ssot_now()
        cls.findings, cls.used_lines = scan(ROOT, cls.ssot)

    def test_no_stale_certified_tier_statement_outside_the_allowlist_9927(self):
        self.assertEqual(self.findings, [], f"{len(self.findings)} stale tier statements:\n" + "\n".join(self.findings))

    def test_every_allowlist_entry_still_matches_9927(self):
        files = set(tracked_files(ROOT))
        for prefix in HISTORY_PREFIXES:
            hit = prefix in files if not prefix.endswith("/") else any(f.startswith(prefix) for f in files)
            self.assertTrue(hit, f"stale allowlist prefix {prefix}")
        # Dead line entries and untracked unreadable entries are findings of scan().
        self.assertEqual(set(load_allowlist()["unreadable"]) - files, set(), "unreadable entries that are not tracked")
        self.assertEqual(set(HISTORY_REGION_FILES) - files, set(), "region entries that are not tracked")
        for rel in HISTORY_REGION_FILES:
            self.assertRegex(read_text(ROOT, rel) or "", HISTORY_BEGIN, f"region entry {rel} holds no region")

    def test_current_docs_state_the_age_provenance_verbatim_9927(self):
        missing = []
        for rel in tracked_files(ROOT):
            if history_reason(rel) or not (rel.startswith(("docs/", "changelog.d/")) or rel.endswith("README.md")):
                continue
            text = read_text(ROOT, rel)
            if not text or not re.search(r"(?i)apache\s+age\W{0,4}1\.7\.0", text):
                continue
            # A tag opens with a letter, "/" or "!"; a bare "<16 GB" or "<=" in prose is not a tag
            # and must not swallow the text up to the next ">".
            flat = re.sub(r"<[A-Za-z/!][^<>]*>", "", text)
            flat = re.sub(r"[*`]", "", re.sub(r"\s+", " ", flat))
            if AGE_PROVENANCE not in flat:
                missing.append(rel)
        self.assertEqual(missing, [], "docs naming Apache AGE 1.7.0 without the exact provenance sentence")


# Every AGE builder: it builds AGE_SOURCE_COMMIT, applies the pinned patch and verifies the result.
AGE_BUILDERS = (
    "deploy/docker-1461/Dockerfile.pg-age-vector",
    ".github/Dockerfile.ci",
    "deploy/do-1461/provision/pg-age/Dockerfile",
    "deploy/do-1461/provision/20_pg_age.sh",
    "infra/do-hive/cloud-init-memory.yaml.tpl",
)


# Consumers that build or assert the tier: (path, pattern built from the SSOT).
def consumer_patterns(ssot):
    pg, age, sha = ssot["EXPECTED_PG_VERSION"], ssot["EXPECTED_AGE_VERSION"], ssot["AGE_SOURCE_COMMIT"]
    pgv = ssot["PGVECTOR_APT_VERSION"].split("-")[0]
    rows = [
        (".github/Dockerfile.ci", rf'postgres={re.escape(pg)}.*age={re.escape(age)}.*pgvector={re.escape(pgv)}'),
        (".github/Dockerfile.ci", re.escape(sha)),
        (".github/workflows/publish-ci-image.yml", re.escape(sha)),
        (".github/workflows/publish-ci-image.yml", rf"pg{re.escape(pg)}-age{re.escape(age)}-pgv{re.escape(pgv)}"),
        (".github/workflows/cert-postgres-age.yml", rf"PostgreSQL {re.escape(pg)}"),
        (".github/workflows/cert-postgres-age.yml", rf"{re.escape(age)}"),
        ("deploy/docker-1461/provision/10_build.sh", r"AGE_SOURCE_COMMIT=\$\{?AGE_SOURCE_COMMIT"),
        ("deploy/docker-1461/Dockerfile.pg-age-vector", r'rev-parse HEAD\)" = "\$\{AGE_SOURCE_COMMIT\}"'),
        ("src/store/postgres/age_version.rs", rf'AGE_VERSION_CANONICAL: &str = "{re.escape(age)}"'),
    ]
    for rel in AGE_BUILDERS:
        rows.append((rel, rf"{re.escape(APPLIER)}[^\n]*--ssot[^\n]*--src"))
        rows.append((rel, rf"{re.escape(APPLIER)}[^\n]*--verify"))
    return rows


class ConsumerTest(unittest.TestCase):
    def test_consumers_name_the_ssot_values_9927(self):
        ssot = ssot_now()
        self.assertTrue(set(EXPECTED_SSOT) <= set(ssot), "SSOT incomplete")
        for rel, pattern in consumer_patterns(ssot):
            self.assertRegex(read_text(ROOT, rel) or "", pattern, rel)

    def test_the_ledger_finds_exactly_the_listed_builders_each_patched_9951(self):
        ssot = ssot_now()
        found = {}
        for rel in tracked_files(ROOT):
            text = read_text(ROOT, rel)
            if text is None or age_build_ledger.file_kind(rel, text) is None:
                continue
            builds = age_build_ledger.builds(rel, text, ssot)
            if builds:
                found[rel] = all(patched for _, patched in builds)
        self.assertEqual(found, {rel: True for rel in AGE_BUILDERS})


# --- executed version assertions (#9968) ------------------------------------
ASSERT_WORKFLOWS = {
    ".github/workflows/cert-postgres-age.yml": "CERT",
    ".github/workflows/publish-ci-image.yml": "CI",
}
CASE_BLOCK = re.compile(r'^[ \t]*case "\$(pg_ver|age_ver|vec_ver)" in\n.*?^[ \t]*esac[ \t]*$', re.M | re.S)
# (pg, age, vector) -> 0 only for the exact certified triple. Written out by hand.
VERSION_TABLE = [
    (("19.0", "1.7.0", "0.8.7"), 0),
    (("19.01", "1.7.0", "0.8.7"), 1),
    (("19.0.1", "1.7.0", "0.8.7"), 1),
    (("19", "1.7.0", "0.8.7"), 1),
    (("19.1", "1.7.0", "0.8.7"), 1),
    (("", "1.7.0", "0.8.7"), 1),
    (("19.0", "1.7.00", "0.8.7"), 1),
    (("19.0", "1.7.0.1", "0.8.7"), 1),
    (("19.0", "1.7", "0.8.7"), 1),
    (("19.0", "", "0.8.7"), 1),
    (("19.0", "1.7.0", "0.8.70"), 1),
    (("19.0", "1.7.0", "0.8.7-1"), 1),
    (("19.0", "1.7.0", "0.8.7.1"), 1),
    (("19.0", "1.7.0", "0.8.6"), 1),
    (("19.0", "1.7.0", ""), 1),
]


def case_script(rel):
    blocks = {m.group(1): m.group(0) for m in CASE_BLOCK.finditer(read_text(ROOT, rel) or "")}
    return blocks


def run_case_blocks(rel, prefix, versions, ssot):
    blocks = case_script(rel)
    script = "\n".join(blocks[v] for v in ("pg_ver", "age_ver", "vec_ver")) + "\nexit 0\n"
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "pg_ver": versions[0], "age_ver": versions[1], "vec_ver": versions[2],
        f"{prefix}_EXPECTED_PG_VERSION": ssot["EXPECTED_PG_VERSION"],
        f"{prefix}_EXPECTED_AGE_VERSION": ssot["EXPECTED_AGE_VERSION"],
        f"{prefix}_EXPECTED_PGVECTOR_VERSION": ssot["PGVECTOR_APT_VERSION"].split("-")[0],
    }
    r = subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True, timeout=30)
    return r.returncode


@unittest.skipUnless(shutil.which("bash"), "the workflow steps run under bash")
class ExactAssertionTest(unittest.TestCase):
    def test_each_workflow_holds_one_block_per_component_9968(self):
        for rel in ASSERT_WORKFLOWS:
            text = read_text(ROOT, rel) or ""
            for var in ("pg_ver", "age_ver", "vec_ver"):
                self.assertEqual(len(re.findall(rf'^[ \t]*case "\${var}" in$', text, re.M)), 1, f"{rel} {var}")

    def test_workflow_version_assertions_are_exact_9968(self):
        ssot = ssot_now()
        for rel, prefix in ASSERT_WORKFLOWS.items():
            for versions, want in VERSION_TABLE:
                got = run_case_blocks(rel, prefix, versions, ssot)
                self.assertEqual(got != 0, want != 0, f"{rel} {versions} exit {got}")


SSOT_FIXTURE = dict(EXPECTED_SSOT, PGVECTOR_APT_VERSION="0.8.7-1.pgdg13+2")
STALE_LINES = [
    "# PostgreSQL 18 + Apache AGE + pgvector",
    "Certified data tier: PostgreSQL 18.6 + Apache AGE 1.8.0 + pgvector 0.8.6",
    "- **Data tier** - PostgreSQL **18.6** + Apache AGE **1.8.0**",
    'LABEL org.opencontainers.image.description="postgres=18.6 age=1.8.0"',
    "name: Certified pg+AGE cells (live PG 18.6 + AGE 1.8.0 + pgvector 0.8.6)",
    'name: "Publish CI image (pg18.6/AGE1.8.0/pgvector0.8.6)"',
    "FROM apache/age:release_PG18_1.6.0",
    "image: pgvector/pgvector:0.8.7-pg18",
    "apt-get install postgresql-server-dev-18",
    'EXPECTED_PG_VERSION="${DOCKER_1461_EXPECTED_PG_VERSION:-18.6}"',
    'PG_MAJOR="${DOCKER_1461_PG_MAJOR:-20}"',
    'EXPECTED_AGE_VERSION="${DOCKER_1461_EXPECTED_AGE_VERSION:-1.8.1}"',
    'AGE_SOURCE_COMMIT="${DOCKER_1461_AGE_SOURCE_COMMIT:-06ce678d00000000000000000000000000000000}"',
    "Apache AGE 1.7.0, built from upstream PG19 branch commit c6b043e",
    "| PostgreSQL | 18.4 |",
    "age-1.8.0-06ce678d",
    "postgresql-18-age=1.8.0~rc0-2.pgdg24.04+1",
    "| pgvector | 0.8.5 |",
    "PG 16 tier with pgvector 0.8.6",
    "AGE 1.6.0 with pgvector 0.8.4",
    "postgres 18.6/AGE",
    '--build-arg "AGE_APT_VERSION=$AGE_APT_VERSION"',
    ': "${AGE_BASE_IMAGE:?docker-1461 SSOT did not define AGE_BASE_IMAGE}"',
]
# One drifted form per container shape (#9966), each with its exact reason.
# None of these is a stale (PG 18 / AGE 1.8) statement: they move the tier
# forward or sideways, which only an allowlist of exact values can catch.
DRIFT_LINES = {
    # literal shell assignment and default
    'PG_VERSION="20.1"': ["pg-binding:PG_VERSION=20.1"],
    'EXPECTED_PGVECTOR_VERSION="${DOCKER_1461_EXPECTED_PGVECTOR_VERSION:-0.9.0}"':
        ["vector-binding:DOCKER_1461_EXPECTED_PGVECTOR_VERSION=0.9.0"],
    # typed constant (Rust)
    'pub const AGE_VERSION_CANONICAL: &str = "1.9.0";': ["age-binding:AGE_VERSION_CANONICAL=1.9.0"],
    "const PG_MAJOR_CERTIFIED: u32 = 20;": ["pg-binding:PG_MAJOR_CERTIFIED=20"],
    "ARG PGVECTOR_REF=v0.8.0": ["vector-binding:PGVECTOR_REF=0.8.0"],
    # alias and camelCase names
    'pgVer = "19.1"': ["pg-binding:pgVer=19.1"],
    "let pgvVersion = \"0.8.70\";": ["vector-binding:pgvVersion=0.8.70"],
    "AGEVER=1.7.00": ["age-binding:AGEVER=1.7.00"],
    # YAML, TOML, JSON, Python dict, tuple/array, match arm, comparison
    "  pg_major: 20": ["pg-binding:pg_major=20"],
    'age_version = "1.9.0"': ["age-binding:age_version=1.9.0"],
    '{"pgvector_version": "0.9.1"}': ["vector-binding:pgvector_version=0.9.1"],
    '("age_version", "1.7.1"),': ["age-binding:age_version=1.7.1"],
    '"postgres_version" => "19.01",': ["pg-binding:postgres_version=19.01"],
    'if server_version_num == 200000:': ["pg-binding:server_version_num=200000"],
    # inexact comparisons
    '${CERT_EXPECTED_PGVECTOR_VERSION}*) echo ok ;;': ["version-prefix-glob:CERT_EXPECTED_PGVECTOR_VERSION"],
    '"$EXPECTED_AGE_VERSION"*) : ;;': ["version-prefix-glob:EXPECTED_AGE_VERSION"],
    "echo \"$v\" | grep -qx 'age=1.7.0' && ok": ["version-grep-inexact"],
    'psql -c "$q" | grep -q "${EXPECTED_PG_VERSION}"': ["version-grep-inexact"],
    # base image
    "FROM postgres:19-trixie AS age-build": ["base-image-not-digest-pinned"],
    "image: docker.io/library/postgres:19-trixie@sha256:" + "0" * 64: ["base-image-digest-differs"],
}
CLEAN_LINES = [
    "Certified data tier: PostgreSQL 19.0 + Apache AGE 1.7.0 + pgvector 0.8.7.",
    'PG_MAJOR="${DOCKER_1461_PG_MAJOR:-19}"',
    'AGE_SOURCE_COMMIT="${DOCKER_1461_AGE_SOURCE_COMMIT:-c6b043d1c8f4909331b9080d6640b487782fc958}"',
    'AGE_PATCH_UPSTREAM_COMMIT="${DOCKER_1461_AGE_PATCH_UPSTREAM_COMMIT:-06ce678d74210539705c77e2dc7c9fa861e2a331}"',
    AGE_PROVENANCE,
    "| auto_tag.rs | D | 85% | 18.4% |",
    "The 18.7k-LOC module split",
    "Apache AGE 1.6.0 alternate matrix on PG 16",
    "average 1.8.0 seconds",
    "transitive through sqlx-core 0.8.6 and sqlx-postgres 0.8.6",
    "> Alternate tested matrix: PG 16 + AGE 1.6.0 + pgvector 0.8.2 is a second tested combination.",
    "new SAL surface for postgres-backed daemons. The 18.7k-LOC module",
    "| postgres.rs | 18.4% |",
    'pub const AGE_VERSION_CANONICAL: &str = "1.7.0";',
    "  pg_major: 19",
    'PG_APT_VERSION="${DOCKER_1461_PG_APT_VERSION:-19.0-2.pgdg13+1}"',
    'PGVECTOR_APT_VERSION="${DOCKER_1461_PGVECTOR_APT_VERSION:-0.8.7-1.pgdg13+2}"',
    'if server_version_num == 190000:',
    '"$CERT_EXPECTED_PGVECTOR_VERSION") echo ok ;;',
    "echo \"$v\" | grep -qxF 'age=1.7.0' && ok",
    "FROM postgres:19-trixie@" + BASE_DIGEST + " AS age-build",
    "postgres://pg:5432/db",
    "pg_pool_size = 20",
]

HB, HE = MARKER_PREFIX + ": begin", MARKER_PREFIX + ": end"


class ScannerTableTest(unittest.TestCase):
    def test_every_stale_form_is_a_finding_9927(self):
        for line in STALE_LINES:
            self.assertNotEqual(line_findings(line, SSOT_FIXTURE), [], line)

    def test_every_drifted_form_is_a_finding_with_its_reason_9966(self):
        for line, want in DRIFT_LINES.items():
            self.assertEqual(line_findings(line, SSOT_FIXTURE), want, line)

    def test_current_forms_are_clean_9927(self):
        for line in CLEAN_LINES:
            self.assertEqual(line_findings(line, SSOT_FIXTURE), [], line)

    def test_exact_reason_names_the_form_9927(self):
        self.assertEqual(line_findings('PG_MAJOR="${DOCKER_1461_PG_MAJOR:-20}"', SSOT_FIXTURE), ["PG_MAJOR=20"])
        self.assertEqual(line_findings("FROM apache/age:release_PG18_1.6.0", SSOT_FIXTURE), ["postgres-18"])

    def test_yaml_parent_supplies_the_tier_of_a_bare_version_key_9966(self):
        cases = [
            ("postgres:\n  version: 20\n", ["f:2: pg-binding:version=20,uncertified-token:20: version: 20"]),
            ("age:\n  image: x\n  version: \"1.9.0\"\n",
             ['f:3: age-binding:version=1.9.0,uncertified-token:1.9.0: version: "1.9.0"']),
            ("pgvector:\n  version: 0.8.7\n", []),
            ("postgres:\n  version: 19\nredis:\n  version: 7\n", []),
        ]
        for text, want in cases:
            self.assertEqual(scan_text("f", text, SSOT_FIXTURE, {"f"})[0], want, text)

    def test_history_region_rules_9927(self):
        stale = "PostgreSQL 18.6 was certified on 2026-08-18"
        cases = [
            ([f"<!-- {HB} (dated note 2026-08-18) -->", stale, f"<!-- {HE} -->"], []),
            ([f"<!-- {HB} -->", stale, f"<!-- {HE} -->"], ["f:1: history-region-no-reason"]),
            ([f"<!-- {HB} (dated note 2026-08-18) -->", "current text", f"<!-- {HE} -->"],
             ["f:1: history-region-holds-no-stale-statement"]),
            ([f"<!-- {HE} -->"], ["f:1: history-region-end-without-begin"]),
            ([f"<!-- {HB} (dated note 2026-08-18) -->", stale], ["f:1: history-region-unclosed"]),
            ([f"<!-- {HB} (dated note 2026-08-18) -->", stale, f"<!-- {HB} (second note) -->", stale, f"<!-- {HE} -->"],
             ["f:3: history-region-nested"]),
            ([f"<!-- {HB} (dated note 2026-08-18) -->"] + [stale] * MAX_HISTORY_REGION_LINES + [f"<!-- {HE} -->"],
             [f"f:1: history-region-over-{MAX_HISTORY_REGION_LINES}-lines"]),
            ([stale, f"<!-- {HB} (dated note 2026-08-18) -->", stale, f"<!-- {HE} -->", stale],
             ["f:1: postgres-18,uncertified-token:18.6,uncertified-token:2026-08-18: " + stale,
              "f:5: postgres-18,uncertified-token:18.6,uncertified-token:2026-08-18: " + stale]),
        ]
        for lines, want in cases:
            self.assertEqual(scan_text("f", "\n".join(lines), SSOT_FIXTURE, {"f"})[0], want, lines)

    def test_history_region_only_in_named_files_9966(self):
        lines = [f"<!-- {HB} (dated note 2026-08-18) -->", "PostgreSQL 18.6 was certified", f"<!-- {HE} -->"]
        self.assertEqual(scan_text("g", "\n".join(lines), SSOT_FIXTURE, {"f"})[0], ["g:1: history-region-in-unlisted-file"])

    def test_age_build_must_apply_the_patch_9965(self):
        build = "git checkout ${AGE_SOURCE_COMMIT}\nmake PG_CONFIG=/usr/bin/pg_config install\n"
        self.assertEqual(age_build_ledger.findings("f.sh", build, SSOT_FIXTURE), ["f.sh:2: age-build-without-patch"])
        patched = build.replace("make", f"python3 {APPLIER} --ssot lib.sh --src . && make")
        self.assertEqual(age_build_ledger.findings("f.sh", patched, SSOT_FIXTURE), [])

    def test_scanner_is_linear_on_a_100k_line_input_9927(self):
        lines = ["x" * 60 + " pg 19 age 1.7.0 " + "y" * 60] * 100_000
        started = time.monotonic()
        hits = sum(1 for line in lines if line_findings(line, SSOT_FIXTURE))
        self.assertEqual(hits, 0)
        self.assertLess(time.monotonic() - started, 20.0)

    def test_new_rules_are_bounded_on_adversarial_100k_inputs_9966(self):
        hostile = [
            "a" * 100_000,
            "pg_version" * 10_000 + "=",
            ("x_" * 50_000) + ": 1",
            "grep " + "-x " * 30_000 + "'19.0",
            "${PG_VERSION" * 8_000,
            "postgres:19" * 9_000,
            ("a: " * 33_000) + "\n",
        ]
        started = time.monotonic()
        for line in hostile:
            line_findings(line, SSOT_FIXTURE)
        scan_text("f", "\n".join(f"{' ' * (i % 40)}k{i}:" for i in range(100_000)), SSOT_FIXTURE, {"f"})
        self.assertLess(time.monotonic() - started, 20.0)


class TreeMutantTest(unittest.TestCase):
    """The whole-tree scan on a small synthetic tree: a planted file outside
    the first directory, an unlisted binary and an unlisted history region
    are each found (#9966)."""

    def setUp(self):
        base = os.environ.get("TMPDIR") or str(ROOT / ".local-runs")
        os.makedirs(base, exist_ok=True)
        self.tree = Path(tempfile.mkdtemp(prefix="cert-tier-", dir=base))
        (self.tree / "aaa").mkdir()
        (self.tree / "aaa" / "ok.md").write_text("PostgreSQL 19.0 + Apache AGE 1.7.0\n")

    def tearDown(self):
        shutil.rmtree(self.tree, ignore_errors=True)

    def scan_tree(self):
        return scan(self.tree, SSOT_FIXTURE, allowlist={"lines": {}, "unreadable": {}})[0]

    def test_clean_tree_has_no_finding_9966(self):
        self.assertEqual(self.scan_tree(), [])

    def test_file_outside_the_first_directory_9966(self):
        (self.tree / "zzz" / "deep").mkdir(parents=True)
        (self.tree / "zzz" / "deep" / "x.toml").write_text('age_version = "1.9.0"\n')
        self.assertEqual(self.scan_tree(), [
            'zzz/deep/x.toml:1: age-binding:age_version=1.9.0,uncertified-token:1.9.0: age_version = "1.9.0"'])

    def test_non_utf8_file_is_scanned_and_must_be_listed_9966(self):
        (self.tree / "blob.bin").write_bytes(b"\xff\xfe\x00PostgreSQL 18.6\n")
        self.assertEqual(self.scan_tree(), [
            "blob.bin: non-utf8-unlisted",
            "blob.bin:1: postgres-18,uncertified-token:18.6: \xff\xfe\x00PostgreSQL 18.6",
        ])

    def test_unlisted_history_region_9966(self):
        (self.tree / "y.md").write_text(f"{HB} (dated note 2026-08-18)\nPostgreSQL 18.6\n{HE}\n")
        self.assertEqual(self.scan_tree(), ["y.md:1: history-region-in-unlisted-file"])


def expected_line_key(line):
    """The allowlist key of one full line, spelled out independently of the
    module: the first 24 hex digits of its sha256, each digit moved onto the
    letters g..v so the allowlist file holds no digit (#9951 r2)."""
    return hashlib.sha256(line.encode("utf-8")).hexdigest()[:24].translate(
        str.maketrans("0123456789abcdef", "ghijklmnopqrstuv"))


class FailClosedMutantTest(unittest.TestCase):
    """Round-2 design call on #9951: both ratchets fail closed by construction.
    On a line that names the tier (any tier word) every numeric token must be
    a certified token derived from lib.sh, or the exact full line is listed
    with a reason; an AGE build is found by what is executed, never by text.
    Each case is a mutant that survived round 1 or a new mutant per form; the
    expected findings are written out by hand."""

    def setUp(self):
        base = os.environ.get("TMPDIR") or str(ROOT / ".local-runs")
        os.makedirs(base, exist_ok=True)
        self.tree = Path(tempfile.mkdtemp(prefix="cert-tier-fc-", dir=base))
        (self.tree / "aaa").mkdir()
        (self.tree / "aaa" / "ok.md").write_text("PostgreSQL 19.0 + Apache AGE 1.7.0\n")

    def tearDown(self):
        shutil.rmtree(self.tree, ignore_errors=True)

    def plant(self, rel, text):
        path = self.tree / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(text, bytes):
            path.write_bytes(text)
        else:
            path.write_text(text)

    def scan_tree(self, allowlist=None):
        return scan(self.tree, SSOT_FIXTURE, allowlist={"lines": {}, "unreadable": {}} if allowlist is None else allowlist)[0]

    # --- the four round-1 survivors --------------------------------------
    def test_survivor_server_version_num_comparison_9951(self):
        self.plant("scripts/probe.py", "if server_version_num >= 180000:\n    ok()\n")
        self.assertEqual(self.scan_tree(), [
            "scripts/probe.py:1: uncertified-token:180000: if server_version_num >= 180000:"])

    def test_survivor_makefile_conditional_assignment_9951(self):
        self.plant("deploy/x/Makefile", "PG_MAJOR ?= 18\n")
        self.assertEqual(self.scan_tree(), ["deploy/x/Makefile:1: uncertified-token:18: PG_MAJOR ?= 18"])

    def test_survivor_stale_line_in_a_formerly_exempt_test_file_9951(self):
        self.plant("scripts/test/test_ensure_age_extension_6161.py", 'WANT = "PostgreSQL 18.6"\n')
        self.assertEqual(self.scan_tree(), [
            'scripts/test/test_ensure_age_extension_6161.py:1: postgres-18,uncertified-token:18.6: WANT = "PostgreSQL 18.6"'])

    def test_survivor_applier_named_only_in_a_comment_9951(self):
        self.plant("deploy/y/Dockerfile", "\n".join([
            "FROM scratch",
            "RUN git clone https://github.com/apache/age.git /src/age \\",
            " && git -C /src/age checkout c6b043d1c8f4909331b9080d6640b487782fc958 \\",
            " # python3 /p/apply_age_patch.py --ssot /p/lib.sh --src /src/age",
            " && make -C /src/age install",
            "",
        ]))
        self.assertEqual(self.scan_tree(), ["deploy/y/Dockerfile:5: age-build-without-patch"])

    # --- one mutant per form of the pin -----------------------------------
    def test_every_form_of_an_uncertified_pin_is_a_finding_9951(self):
        forms = {
            # literal
            "f/literal.md": ("Runs on PostgreSQL 20 only.\n", ["uncertified-token:20"]),
            # typed constant whose name carries a non-neutral word
            "f/typed.rs": ("const PG_FLOOR: u32 = 17;\n", ["uncertified-token:17"]),
            # alias name
            "f/alias.py": ("pg_tier_alias = 20\n", ["uncertified-token:20"]),
            # YAML flow list under a non-version key
            "f/list.yml": ("  pg_supported: [17, 20]\n", ["uncertified-token:17", "uncertified-token:20"]),
            # match arm with the value first
            "f/arm.rs": ('    20 => "postgres",\n', ["uncertified-token:20"]),
            # a file outside the first directory scanned
            "zzz/deep/q.toml": ("postgres = 17\n", ["uncertified-token:17"]),
        }
        for rel, (text, _) in forms.items():
            self.plant(rel, text)
        want = sorted(f"{rel}:1: {','.join(reasons)}: {text.strip()}" for rel, (text, reasons) in forms.items())
        self.assertEqual(sorted(self.scan_tree()), want)

    def test_certified_tokens_and_untiered_lines_are_clean_9951(self):
        self.plant("g/clean.md", "\n".join([
            "PostgreSQL 19 (server_version_num 190000), AGE 1.7.0, pgvector 0.8.7.",
            "postgresql-19=19.0-2.pgdg13+1 postgresql-19-pgvector=0.8.7-1.pgdg13+2",
            "AGE commit c6b043d plus 06ce678d74210539705c77e2dc7c9fa861e2a331",
            "The cache holds 512 entries for 30 seconds.",
            "",
        ]))
        self.assertEqual(self.scan_tree(), [])

    # --- the allowlist ---------------------------------------------------
    def test_listed_line_passes_once_per_entry_9951(self):
        line = "Runs on PostgreSQL 20 only."
        self.plant("h/doc.md", f"{line}\n{line}\n")
        one = {"lines": {"h/doc.md": [[expected_line_key(line), "DOC"]]}, "unreadable": {}}
        self.assertEqual(self.scan_tree(one), [f"h/doc.md:2: uncertified-token:20: {line}"])
        two = {"lines": {"h/doc.md": [[expected_line_key(line), "DOC"]] * 2}, "unreadable": {}}
        self.assertEqual(self.scan_tree(two), [])

    def test_dead_allowlist_entries_are_findings_9951(self):
        gone, stale = expected_line_key("no such line"), expected_line_key("PostgreSQL 19.0 + Apache AGE 1.7.0")
        allow = {
            "lines": {"aaa/ok.md": [[stale, "DOC"]], "gone.md": [[gone, "DOC"]]},
            "unreadable": {"aaa/ok.md": "not binary at all"},
        }
        self.assertEqual(self.scan_tree(allow), [
            "aaa/ok.md: unreadable-entry-is-utf8",
            f"aaa/ok.md: dead-allowlist-entry:{stale}",
            f"gone.md: dead-allowlist-entry:{gone}",
        ])

    def test_unknown_reason_is_a_finding_9951(self):
        line = "Runs on PostgreSQL 20 only."
        self.plant("h/doc.md", f"{line}\n")
        allow = {"lines": {"h/doc.md": [[expected_line_key(line), "BECAUSE"]]}, "unreadable": {}}
        self.assertEqual(self.scan_tree(allow), [f"h/doc.md: allowlist-entry-bad-reason:{expected_line_key(line)}"])

    def test_listed_binary_still_has_its_lines_scanned_9951(self):
        self.plant("docs/logo.jpg", b"\xff\xd8\xffPostgreSQL 18.6\n")
        allow = {"lines": {}, "unreadable": {"docs/logo.jpg": "logo image (JPEG)"}}
        self.assertEqual(self.scan_tree(allow), ["docs/logo.jpg:1: postgres-18,uncertified-token:18.6: \xff\xd8\xffPostgreSQL 18.6"])

    def test_allowlist_type_has_no_whole_file_field_9951(self):
        self.assertEqual(set(load_allowlist()), {"lines", "unreadable"})
        for rel, entries in load_allowlist()["lines"].items():
            self.assertIsInstance(entries, list, rel)
            for entry in entries:
                self.assertEqual(len(entry), 2, rel)
                self.assertRegex(entry[0], r"^[g-v]{24}$", rel)
                self.assertIn(entry[1], ALLOW_REASONS, rel)

    # --- the ledger: an AGE build is what is executed ---------------------
    def test_sixth_builder_without_the_applier_9951(self):
        self.plant("infra/x/build.sh", "\n".join([
            "#!/bin/sh",
            "git clone https://github.com/apache/age.git /opt/age",
            "cd /opt/age",
            "make PG_CONFIG=/usr/bin/pg_config install",
            "",
        ]))
        self.assertEqual(self.scan_tree(), ["infra/x/build.sh:4: age-build-without-patch"])

    def test_short_sha_checkout_then_bare_make_9951(self):
        self.plant("b/n5.sh", "#!/bin/bash\nset -e\ngit -C /opt/src checkout c6b043d1\nmake -j4\n")
        self.assertEqual(self.scan_tree(), ["b/n5.sh:4: age-build-without-patch"])

    def test_applier_in_an_echo_string_does_not_patch_9951(self):
        self.plant("b/echo.sh", "#!/bin/sh\necho python3 apply_age_patch.py\nmake -C /src/age install\n")
        self.assertEqual(self.scan_tree(), ["b/echo.sh:3: age-build-without-patch"])

    def test_workflow_run_block_builder_9951(self):
        self.plant(".github/workflows/w.yml", "\n".join([
            "jobs:",
            "  b:",
            "    steps:",
            "      - run: |",
            "          git clone https://github.com/apache/age.git age-src",
            "          make -C age-src install",
            "",
        ]))
        self.assertEqual(self.scan_tree(), [".github/workflows/w.yml:6: age-build-without-patch"])

    def test_python_subprocess_builder_9951(self):
        self.plant("tools/b.py", "\n".join([
            "import subprocess",
            "# apply_age_patch.py is named only here",
            'subprocess.run(["make", "-C", "/src/age", "install"], check=True)',
            "",
        ]))
        self.assertEqual(self.scan_tree(), ["tools/b.py:3: age-build-without-patch"])

    def test_patched_builders_of_every_kind_are_clean_9951(self):
        apply = "python3 /p/apply_age_patch.py --ssot /p/lib.sh --src /src/age"
        self.plant("k/Dockerfile", f"FROM scratch\nRUN git clone https://github.com/apache/age.git /src/age \\\n && {apply} \\\n && make -C /src/age install\n")
        self.plant("k/b.sh", f"#!/bin/sh\nset -e\ncd /src/age\n{apply}\nmake PG_CONFIG=/usr/bin/pg_config install\n")
        self.plant("k/w.yml", f"steps:\n  - run: |\n      {apply}\n      make -C /src/age install\n")
        self.plant("k/b.py", "\n".join([
            "import subprocess",
            'subprocess.run(["python3", "/p/apply_age_patch.py", "--ssot", "/p/lib.sh", "--src", "/src/age"], check=True)',
            'subprocess.run(["make", "-C", "/src/age", "install"], check=True)',
            "",
        ]))
        self.assertEqual(self.scan_tree(), [])

    def test_applier_and_its_tests_are_not_builders_9951(self):
        # Prose, docstrings and argv that never run make: the text names the
        # AGE commit and a make line, but nothing executes a build (#9981).
        self.plant("deploy/docker-1461/provision/apply_age_patch.py", "\n".join([
            '"""Run between the checkout of AGE_SOURCE_COMMIT and make PG_CONFIG=/x install."""',
            "import subprocess",
            'subprocess.run(["git", "apply", "-"], check=True)',
            "",
        ]))
        self.plant("scripts/test/test_x.py", "\n".join([
            "BUILD = 'git checkout c6b043d1c8f4909331b9080d6640b487782fc958 && make -j4 install'",
            "",
        ]))
        self.assertEqual(self.scan_tree(), [])


PRINT_MISSING_FLAG = "--print-missing"
UNREADABLE_SEED = {
    "OIN_LICENSE_AGREEMENT.pdf": "signed licence agreement (PDF)",
    "docs/ai-memory-logo.jpg": "logo image (JPEG)",
}


def print_missing():
    """Print the allowlist the tree needs now: every finding line keyed, with
    its present reason when it is listed and the reason of its path when it
    is new. A reviewer reads the diff of the allowlist file, line by line."""
    present = {}
    try:
        current = load_allowlist()
    except (OSError, ValueError):
        current = {"lines": {}, "unreadable": dict(UNREADABLE_SEED)}
    for rel, entries in current.get("lines", {}).items():
        for key, reason in entries:
            present.setdefault((rel, key), reason)
    missing = []
    scan(ROOT, ssot_now(), allowlist={"lines": {}, "unreadable": current.get("unreadable", UNREADABLE_SEED)},
         missing=missing)
    lines = {}
    for rel, stripped in missing:
        key = line_key(stripped)
        lines.setdefault(rel, []).append([key, present.get((rel, key), path_reason(rel))])
    unreadable = dict(sorted(current.get("unreadable", UNREADABLE_SEED).items()))
    # One entry per line, so the diff of the file is a diff of lines.
    parts = ['{"lines": {']
    for i, (rel, entries) in enumerate(sorted(lines.items())):
        body = ",\n".join(f"  {json.dumps(entry)}" for entry in entries)
        parts.append(f"{json.dumps(rel)}: [\n{body}\n]{',' if i < len(lines) - 1 else ''}")
    parts.append('}, "unreadable": ' + json.dumps(unreadable, indent=1) + "}")
    print("\n".join(parts))


if __name__ == "__main__":
    if sys.argv[1:] == [PRINT_MISSING_FLAG]:
        print_missing()
    else:
        unittest.main()
