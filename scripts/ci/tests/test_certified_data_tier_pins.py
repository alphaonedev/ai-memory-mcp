"""Certified data tier ratchet over the whole tracked tree (#9927).

Operator orders c4f4d408 and 111f59db (ai-memory, p10): the certified data
tier is PostgreSQL 19 (19.0) + Apache AGE 1.7.0 + pgvector 0.8.7. Apache AGE
1.7.0 is built from upstream PG19 branch commit c6b043d (not a tagged Apache
release; upstream has no 1.7.0 release for PostgreSQL 19).

The one source of truth is deploy/docker-1461/provision/lib.sh. This module
holds the invariant four ways:

* The SSOT itself carries the triple and the full AGE commit sha. The expected
  values are written out here by hand from the operator orders, never read
  from the code under test.
* Every tracked text file is scanned for a stale-tier statement (PostgreSQL
  18 in any spelling, Apache AGE 1.8.x, pgvector below 0.8.7) and for any
  shell default or assignment of a tier variable, any AGE commit sha and any
  short form of it that differs from the SSOT. The permitted sites are an
  ALLOWLIST: whole history paths (released changelogs, dated reviews, audits,
  campaign records, an immutable migration) and exact lines, each with its
  reason. An allowlist entry that no longer matches anything fails, so the
  list cannot rot.
* The consumers that build or assert the tier name the SSOT values.
* The scanner is table-tested over every stale form and bounded in time on
  a 100K-line input.

CERT_TIER_ROOT points the scan at another tree (an exported base or a
mutated copy) for the red-at-base and mutation proofs.
"""
import os
import re
import subprocess
import time
import unittest
from pathlib import Path

ROOT = Path(os.environ.get("CERT_TIER_ROOT") or Path(__file__).resolve().parents[3])
SSOT_PATH = "deploy/docker-1461/provision/lib.sh"

# Written by hand from operator orders c4f4d408 / 111f59db and the conductor's
# AGE source pin (independent of the code under test).
EXPECTED_SSOT = {
    "PG_BASE_IMAGE": "postgres:19-trixie",
    "PG_MAJOR": "19",
    "EXPECTED_PG_VERSION": "19.0",
    "EXPECTED_AGE_VERSION": "1.7.0",
    "AGE_SOURCE_REPO": "https://github.com/apache/age.git",
    "AGE_SOURCE_COMMIT": "c6b043d1c8f4909331b9080d6640b487782fc958",
}
EXPECTED_PGVECTOR_PREFIX = "0.8.7-"
SHORT_SHA_LEN = 7

# The exact wording every current doc and the changelog use for the AGE build.
AGE_PROVENANCE = (
    "Apache AGE 1.7.0, built from upstream PG19 branch commit c6b043d (not a "
    "tagged Apache release; upstream has no 1.7.0 release for PostgreSQL 19)"
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
}
# A bare tier minor counts when the same line talks about the data tier. A
# bare 0.8.x counts only beside pgvector (sqlx-postgres is also 0.8.x).
TIER_WORD = re.compile(r"(?i)postgres|\bpg(?![a-z])|pgdg|pgvector|\bage\b|apache age")
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
    r"AGE_SOURCE_COMMIT)\b(?:\}|\"|')?\s*(?::-|=|:\s)\s*[\"']?([0-9a-f][0-9a-f.]*)"
)
FULL_SHA = re.compile(r"(?i)(?:age[\w-]*commit|age_source|age@|apache/age[^\s]*?)[^0-9a-f]{0,40}\b([0-9a-f]{40})\b")
SHORT_SHA = re.compile(r"(?i)\bcommit\s+([0-9a-f]{7,40})\b")

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
    "docs/release-v0.7.1.html": "v0.7.1 release page, history",
    "docs/whats-new-v063.html": "v0.6.3 release page, history",
    "docs/v070-changelog.html": "v0.7.0 changelog page, history",
    "docs/evidence/index.html": "index of captured evidence runs, history",
    "docs/bench/": "dated benchmark evidence",
    "migrations/postgres/0045_v88_list_composite_indexes.sql": "applied migrations are immutable",
    "scripts/ci/tests/test_certified_data_tier_pins.py": "this ratchet names the stale forms",
}
# (path, exact substring of the line): reason.
LINE_ALLOW = {
    (".github/workflows/mobile-runtime.yml", "(iOS 18.5/18.6)"): "iOS simulator versions, not the data tier",
    ("tests/qual_10_module_size_ceiling.rs", "after the AGE-1.8.0 comment rewrite"): "dated ceiling-bump history (#3297)",
    ("changelog.d/3297.docs.md", "Re-verified on AGE **1.8.0**"): "records the tier #3297 was verified on",
}


def tracked_files(root):
    if (root / ".git").exists():
        out = subprocess.run(["git", "-C", str(root), "ls-files", "-z"], capture_output=True, check=True).stdout
        return sorted(p.decode() for p in out.split(b"\0") if p)
    return sorted(str(p.relative_to(root)) for p in root.rglob("*") if p.is_file())


def read_text(root, rel):
    try:
        return (root / rel).read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return None


def parse_ssot(text):
    """Shell defaults `VAR="${DOCKER_1461_VAR:-value}"` from the SSOT."""
    found = {}
    for m in re.finditer(r'^([A-Z_]+)="\$\{DOCKER_1461_\1:-([^}]*)\}"', text, re.M):
        found[m.group(1)] = m.group(2)
    return found


def history_reason(rel):
    for prefix, reason in HISTORY_PREFIXES.items():
        if rel == prefix or (prefix.endswith("/") and rel.startswith(prefix)):
            return reason
    return None


def line_findings(line, ssot):
    """Every stale-tier reason the one line carries (empty when clean)."""
    alternate = all(rx.search(line) for rx in ALTERNATE)
    reasons = [name for name, rx in STALE_FORMS.items() if rx.search(line) and not (alternate and name == "pgvector-old")]
    if not reasons and TIER_WORD.search(line) and BARE_STALE.search(line):
        reasons.append("bare-stale-version")
    if not reasons and not alternate and VECTOR_WORD.search(line) and BARE_OLD_VECTOR.search(line):
        reasons.append("bare-stale-pgvector")
    for m in TIER_VAR.finditer(line):
        var, value = m.group(1), m.group(2)
        want = ssot.get(var)
        if want is not None and value != want:
            reasons.append(f"{var}={value}")
    sha = ssot.get("AGE_SOURCE_COMMIT", "")
    for m in FULL_SHA.finditer(line):
        if m.group(1).lower() != sha:
            reasons.append(f"age-sha={m.group(1)}")
    if "PG19" in line or "AGE 1.7.0" in line or "age_source" in line.lower():
        for m in SHORT_SHA.finditer(line):
            if not sha.startswith(m.group(1).lower()):
                reasons.append(f"age-short-sha={m.group(1)}")
    return reasons


def scan(root, ssot):
    findings, used_lines = [], set()
    for rel in tracked_files(root):
        if history_reason(rel):
            continue
        text = read_text(root, rel)
        if text is None:
            continue
        for n, line in enumerate(text.splitlines(), 1):
            reasons = line_findings(line, ssot)
            if not reasons:
                continue
            allowed = [k for k in LINE_ALLOW if k[0] == rel and k[1] in line]
            if allowed:
                used_lines.update(allowed)
                continue
            findings.append(f"{rel}:{n}: {','.join(reasons)}: {line.strip()[:160]}")
    return findings, used_lines


class SsotTest(unittest.TestCase):
    def test_ssot_carries_the_certified_triple_and_age_sha_9927(self):
        ssot = parse_ssot(read_text(ROOT, SSOT_PATH) or "")
        for var, want in EXPECTED_SSOT.items():
            self.assertEqual(ssot.get(var), want, f"{SSOT_PATH} {var}")
        self.assertTrue(ssot.get("PGVECTOR_APT_VERSION", "").startswith(EXPECTED_PGVECTOR_PREFIX), ssot)
        self.assertNotIn("AGE_APT_VERSION", ssot, "AGE is a pinned-commit source build, not an apt package")


class WholeTreeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ssot = parse_ssot(read_text(ROOT, SSOT_PATH) or "")
        cls.findings, cls.used_lines = scan(ROOT, cls.ssot)

    def test_no_stale_certified_tier_statement_outside_the_allowlist_9927(self):
        self.assertEqual(self.findings, [], f"{len(self.findings)} stale tier statements:\n" + "\n".join(self.findings))

    def test_every_allowlist_entry_still_matches_9927(self):
        files = set(tracked_files(ROOT))
        for prefix in HISTORY_PREFIXES:
            hit = prefix in files if not prefix.endswith("/") else any(f.startswith(prefix) for f in files)
            self.assertTrue(hit, f"stale allowlist prefix {prefix}")
        self.assertEqual(set(LINE_ALLOW) - self.used_lines, set(), "stale line allowlist entries")

    def test_current_docs_state_the_age_provenance_verbatim_9927(self):
        missing = []
        for rel in tracked_files(ROOT):
            if history_reason(rel) or not (rel.startswith(("docs/", "changelog.d/")) or rel.endswith("README.md")):
                continue
            text = read_text(ROOT, rel)
            if not text or not re.search(r"(?i)apache\s+age\W{0,4}1\.7\.0", text):
                continue
            flat = re.sub(r"<[^>]+>", "", text)
            flat = re.sub(r"[*`]", "", re.sub(r"\s+", " ", flat))
            if AGE_PROVENANCE not in flat:
                missing.append(rel)
        self.assertEqual(missing, [], "docs naming Apache AGE 1.7.0 without the exact provenance sentence")


# Consumers that build or assert the tier: (path, pattern built from the SSOT).
def consumer_patterns(ssot):
    pg, age, sha = ssot["EXPECTED_PG_VERSION"], ssot["EXPECTED_AGE_VERSION"], ssot["AGE_SOURCE_COMMIT"]
    pgv = ssot["PGVECTOR_APT_VERSION"].split("-")[0]
    return [
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


class ConsumerTest(unittest.TestCase):
    def test_consumers_name_the_ssot_values_9927(self):
        ssot = parse_ssot(read_text(ROOT, SSOT_PATH) or "")
        self.assertTrue(set(EXPECTED_SSOT) <= set(ssot), "SSOT incomplete")
        for rel, pattern in consumer_patterns(ssot):
            self.assertRegex(read_text(ROOT, rel) or "", pattern, rel)


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
]
CLEAN_LINES = [
    "Certified data tier: PostgreSQL 19.0 + Apache AGE 1.7.0 + pgvector 0.8.7.",
    'PG_MAJOR="${DOCKER_1461_PG_MAJOR:-19}"',
    'AGE_SOURCE_COMMIT="${DOCKER_1461_AGE_SOURCE_COMMIT:-c6b043d1c8f4909331b9080d6640b487782fc958}"',
    AGE_PROVENANCE,
    "| auto_tag.rs | D | 85% | 18.4% |",
    "The 18.7k-LOC module split",
    "Apache AGE 1.6.0 alternate matrix on PG 16",
    "average 1.8.0 seconds",
    "transitive through sqlx-core 0.8.6 and sqlx-postgres 0.8.6",
    "> Alternate tested matrix: PG 16 + AGE 1.6.0 + pgvector 0.8.2 is a second tested combination.",
    "new SAL surface for postgres-backed daemons. The 18.7k-LOC module",
    "| postgres.rs | 18.4% |",
]


class ScannerTableTest(unittest.TestCase):
    def test_every_stale_form_is_a_finding_9927(self):
        for line in STALE_LINES:
            self.assertNotEqual(line_findings(line, SSOT_FIXTURE), [], line)

    def test_current_forms_are_clean_9927(self):
        for line in CLEAN_LINES:
            self.assertEqual(line_findings(line, SSOT_FIXTURE), [], line)

    def test_exact_reason_names_the_form_9927(self):
        self.assertEqual(line_findings('PG_MAJOR="${DOCKER_1461_PG_MAJOR:-20}"', SSOT_FIXTURE), ["PG_MAJOR=20"])
        self.assertEqual(line_findings("FROM apache/age:release_PG18_1.6.0", SSOT_FIXTURE), ["postgres-18"])

    def test_scanner_is_linear_on_a_100k_line_input_9927(self):
        lines = ["x" * 60 + " pg 19 age 1.7.0 " + "y" * 60] * 100_000
        started = time.monotonic()
        hits = sum(1 for line in lines if line_findings(line, SSOT_FIXTURE))
        self.assertEqual(hits, 0)
        self.assertLess(time.monotonic() - started, 20.0)


if __name__ == "__main__":
    unittest.main()
