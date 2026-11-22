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
* Every tracked file is scanned (a file that is not UTF-8 is decoded as
  latin-1 and scanned, and must be listed in BINARY_PATHS with its reason).
  A finding is: a stale-tier statement (PostgreSQL 18 in any spelling, Apache
  AGE 1.8.x, pgvector below 0.8.7); a binding of a tier key to a version
  other than the certified one, in any form (shell default or assignment,
  typed constant, alias, YAML key or YAML parent, a quoted key in a dict,
  JSON object, tuple or match arm); an AGE commit sha or short sha other than
  the two pins; a postgres:19 image reference without the SSOT digest; a
  prefix glob or a non-exact grep over a tier version; an AGE build that does
  not apply the pinned patch. The permitted sites are an ALLOWLIST: whole
  history paths (released changelogs, dated reviews, audits, campaign
  records, an immutable migration) and exact FULL lines, each with its
  reason. An allowlist entry that no longer matches fails, so the list
  cannot rot.
* The consumers that build or assert the tier name the SSOT values, and
  every AGE builder runs the patch applier.
* The version assertions of the workflows are executed over a table of near
  misses (19.01, 1.7.00, 0.8.70 ...) and must refuse every one.
* The scanner is table-tested over every stale and drifted form and bounded
  in time on 100K-line inputs.

CERT_TIER_ROOT points the scan at another tree (an exported base or a
mutated copy) for the red-at-base and mutation proofs.
"""
import hashlib
import os
import re
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(os.environ.get("CERT_TIER_ROOT") or Path(__file__).resolve().parents[3])
SSOT_PATH = "deploy/docker-1461/provision/lib.sh"
PATCH_DIR = "deploy/docker-1461/provision/patches"
APPLIER = "apply_age_patch.py"

# Written by hand from operator orders c4f4d408 / 111f59db, the conductor's
# AGE source pin and the #9965 patch decision (independent of the code under
# test). The digest is the one postgres:19-trixie had at certification
# (#9969); the patch sha256 is of the repo file, the patched sha256 is of
# src/backend/catalog/ag_catalog.c after the patch on AGE_SOURCE_COMMIT.
BASE_DIGEST = "sha256:bb6e70add742cd868fb62cb3b2f67d1dd2bdd2b65a521e778420748753687c60"
EXPECTED_SSOT = {
    "PG_BASE_IMAGE": "postgres:19-trixie@" + BASE_DIGEST,
    "PG_MAJOR": "19",
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

# --- the AGE patch is applied by every AGE build (#9965) ---------------------
AGE_BUILD_MAKE = re.compile(r"\bmake\b[^\n]*(?:PG_CONFIG|install|-j)")
AGE_SOURCE_NAMED = re.compile(r"AGE_SOURCE_COMMIT|c6b043d1c8f4909331b9080d6640b487782fc958")

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
# Tracked files that are not UTF-8. They are still scanned (as latin-1); a
# file missing here, or listed here and UTF-8, is a finding.
BINARY_PATHS = {
    "OIN_LICENSE_AGREEMENT.pdf": "signed licence agreement (PDF)",
    "docs/ai-memory-logo.jpg": "logo image (JPEG)",
}
# A dated history note inside a current doc: the reason is mandatory, the
# region is capped so a current section cannot hide inside one, and only
# these files may hold one (#9966).
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
REQUIRED_CERT_CONTEXT = "Certified pg+AGE cells (live PG 18.6 + AGE 1.8.0 + pgvector 0.8.6)"
# (path, the FULL stripped line): reason.
LINE_ALLOW = {
    ('.github/workflows/cert-postgres-age.yml',
     'name: "Certified pg+AGE cells (live PG 18.6 + AGE 1.8.0 + pgvector 0.8.6)"'):
        'the required-check context name branch protection holds for the cert job',
    ('scripts/qc-allowlists/required-contexts-release.txt',
     'Certified pg+AGE cells (live PG 18.6 + AGE 1.8.0 + pgvector 0.8.6)'):
        'the required-check context name branch protection holds for the cert job',
    ('scripts/qc-allowlists/required-contexts-release.txt',
     '#     `Certified pg+AGE cells (live PG 18.6 + AGE 1.8.0 + pgvector 0.8.6)`'):
        'the required-check context name branch protection holds for the cert job',
    ('scripts/qc-allowlists/required-contexts-live-pin.txt',
     'Certified pg+AGE cells (live PG 18.6 + AGE 1.8.0 + pgvector 0.8.6)'):
        'the required-check context name branch protection holds for the cert job',
    ('scripts/qc-allowlists/required-contexts-joblevel-if-allow.txt',
     'Certified pg+AGE cells (live PG 18.6 + AGE 1.8.0 + pgvector 0.8.6)'):
        'the required-check context name branch protection holds for the cert job',
    ('scripts/ci/tests/test_rust_cache_save_scope_9681.py',
     '"cert-postgres-age": "Certified pg+AGE cells (live PG 18.6 + AGE 1.8.0 + pgvector 0.8.6)",'):
        'the required-check context name branch protection holds for the cert job',
    ('scripts/ci/tests/test_docs_only_gate_9683.py',
     '"Certified pg+AGE cells (live PG 18.6 + AGE 1.8.0 + pgvector 0.8.6)"},'):
        'the required-check context name branch protection holds for the cert job',
    ('tests/qual_10_module_size_ceiling.rs',
     '("src/store/postgres.rs", 43_400), /* 2026-09-23 (#3883/#3882 AGE orphaned-graph structural classification, 5-agent vote 4d3ea1c5 option A): the orphan reason/prefix/signature consts + `is_age_graph_orphan` + the two `ag_catalog.ag_graph` registry probes (tx-savepoint-wrapped + pool) + the shared `record_failed_age_projection` absorb helper + the A2 orphan probe in `project_link_into_age` + the A4 third-reason arms on `warn_age_fallback`/`_pair` + the A3 drainer self-heal + the A6/#3882 `ensure_memory_graph` boot orphan WARN + the #2511 orphan assertion + the sqlite-free classifier unit test bring this file to MEASURED 43_164 on the REBASED tree (carrier eee7bf2e2, `wc -l` = `content.lines().count()`, the qual_10 gate instrument). RE-MEASURED after the rebase per the #2627/#3520 no-carried-ceiling lesson: the pre-rebase base 5a9b50731 measured 43_195, but Boids items 1+2 shrank the carrier ~31 lines, so the rebased figure is 43_164 -- a ceiling carried across a rebase is UNVERIFIED until re-measured. At 43_164 the file FITS under the 43_400 ceiling with 236 headroom -- the additions did NOT overflow it. The #3883 drainer-gate follow-up (gate_record_stop at the top of drain_kg_projection_outbox + the interval-loop record-stop warn-suppression, #3883/#3942) brings this file to 43_199, still under 43_400 with 201 headroom. They land inline because each reads the enclosing tx/loop state (the projection savepoints, the create_graph error branch, the per-edge ids) and cannot be extracted without threading the transaction out of this file. The bump 43_200 -> 43_400 RESTORES the ceiling\'s headroom policy (+236 over the rebased measure 43_164, lockstep, never lower), it does not react to an overflow. PRIOR: 2026-09-15 (Consolidation Unit 1 #3690 #3695 #3691 #3693 #3626 #3699, RE-CUT onto the corrected tree 23d414b17, which had taken the merger bump 42_600 -> 42_700 at MEASURED 42_623): the branch alone measured 42_981 on 1ec64196b and asked for 43_100; the STACKED tree measures 43_063 — 37 lines of headroom, below the ~70 this file keeps so the next unrelated line cannot red a branch that did nothing wrong. Ceiling 43_100 -> 43_200 (+137 headroom, lockstep, never lower). The branch-alone measurement: the title-slot admission helpers (`pg_title_slot_holder` / `pg_same_id_hidden_row_under_key` / `pg_title_slot_admission`), the `TITLE_SLOT_CONFLICT_TARGET` + merge-backstop rewrite of the eight `ON CONFLICT (title, namespace)` literals (now `format!`-built), the by-id tombstone restore arm, the guarded consolidation tombstone UPDATE, the visible-only `find_contradictions` / `find_by_title_namespace`, the #3626 owner-drop suffix on every arm, `migrate_v100`, and the #3699 cross-id merge WARN grow this file to MEASURED 42_981 on this branch alone. A merger bump to 42_700 was taken on the corrected #3654/#3655 tree (measured 42_623 there); the two stack, so the fleet value must be re-measured on the combined tip. Never lower. Ceiling 42_600 -> 43_100 (+119 headroom, lockstep). PRIOR: #3297 re-MEASURED 42_414 on 1880b1cc (`wc -l` after the AGE-1.8.0 comment rewrite; ceiling 42_500 unchanged, 86 headroom). PRIOR: 2026-09-08 (#3423 reflect owner + `reflects_on` edge attestation parity, REBASED onto release/v1.0.0 02580a51): the postgres `reflect_with_hooks` `memory_links` INSERT now SIGNS each `reflects_on` edge with `hooks.active_keypair` over the same `SignableLink` CBOR the sqlite twin signs (pre-image + `attest_level`/`observed_by` binds, stamped once through #3422 `canonical_created_at_stamp`), +61 lines that cannot live in a submodule: the block signs INSIDE the open `tx` and reads the per-edge `src_id` of the enclosing loop, so extracting it would have to thread the transaction out of this file. BUMPED ONLY BY THE REBASE, and that is the whole point of re-measuring: on its own base (70c20c8d) this file was 40_584 and the branch landed 40_645 under the then-ceiling 40_680, needing NO bump — the tip has since grown to 42_344 with only 56 headroom under 42_400, so the identical +61 now overflows by 5. A ceiling carried across a rebase is UNVERIFIED until re-measured (the #2627 / #3520 lesson). MEASURED 42_405 on the rebased tree. Ceiling 42_400 -> 42_500 (+95 headroom, lockstep, never lower). PRIOR: 2026-09-07 (#3520 pg deadlock retry + bootstrap catalog pre-check, REBASED onto integration/f1 5fef2eb8): the six destructive-funnel bodies (`size_gc` / `run_gc` / `forget` / `archive_restore` / `archive_by_ids` / `delete`) rewrapped in the shared `tx_retry::TxRetry` loop with their data-integrity rationale, the bootstrap catalog pre-check wiring in `connect_with_dim`, the two new submodule declarations and the `PG_BOOTSTRAP_TEST_LOCK` cfg(test) guard land this file at MEASURED 42_311 on the rebased tree. RE-DERIVED after the rebase rather than carried forward: the pre-rebase branch measured 42_419 and asked for 42_500, but #3527 moved 161 lines of chain-append allocation OUT into `src/store/postgres/chain_append.rs`, so the merged file needs far less — the #2627 lesson that a ceiling arriving through a merge is UNVERIFIED until re-measured, applied to a rebase. The retry driver and the DDL filter themselves live in NEW modules (`src/store/postgres/tx_retry.rs`, `src/store/postgres/bootstrap_ddl.rs`) per the submodule-over-bump rule; what lands here is only the per-funnel wrapping that cannot live elsewhere. Never lower. Ceiling 42_250 -> 42_400 (+89 headroom, lockstep). PRIOR: 2026-09-06 (#3525 pg connect-lock probe ladder): the probe schedule moved OUT of this file into the new `src/store/pg_migration_lock.rs` (MIGRATION_LOCK_POLL_BASE_MS / _MAX_MS and the MigrationLockProbeLadder that walks them), so this file NETS SMALLER at MEASURED 42_183. Ceiling deliberately left at 42_250 rather than tightened: the shrink is a module extraction, not headroom earned by this file, and re-tightening would only have to be undone by the next pg change. PRIOR: 2026-09-06 (#3519 pg bootstrap/migrate advisory-lock wait): the poll-based `acquire_migration_advisory_lock` helper (bounded doubling `pg_try_advisory_lock` backoff, progress logging, fail-closed refusal), its five budget/cadence consts, the shared `prepare_migration_lock_connection` / `release_migration_advisory_lock` pair (which also closes the #3074 leak on the acquire-failure exits), the two rewired lock sites, the `the_lock_wait_budget_tracks_the_index_build_budget_3519` unit test and the widened CIC design note grow this file to MEASURED 42_187. Never lower. Ceiling 42_000 -> 42_250 (+63 headroom, lockstep). PRIOR: 2026-09-06 (Master lockstep on the COMBINED tip 486db24f = 87f86a0a + #3345 + integration/f1 (#3064 #3075 …) + #3516): MEASURED 41_904 on the merged tree. Each lane measured on its own base (#3075 saw 41_729; the #3345 amendment reverted to 41_800 after its rollup rewrite) but the growth STACKS across the merge, so the fleet value is taken on the combined tip at the final gate. Ceiling 41_800 -> 42_000 (+96 headroom, lockstep, never lower). PRIOR: 2026-09-05 (#3424 kg/query wire-shape parity): the bounded `hydrate_kg_query_rows` step (targets via ANY, last-hop edges via UNNEST on the full (source_id,target_id,relation) key) in both AGE and CTE traversals grows this file to MEASURED 41_676. Never lower the 39_350 floor. Ceiling 41_600 -> 41_800 (+124 headroom, lockstep). PRIOR: 2026-09-02 (#3419 attested-write replay ledger): the v95 `MIGRATION_V95_ATTESTED_WRITE_LEDGER` include + `migrate_v95` + its dispatch arm, the settled-arm literal-94 stamp fix on `migrate_v94`, and the `admit_attested_write` SAL impl (the admit-once `INSERT ... ON CONFLICT DO NOTHING` whose PRIMARY KEY IS the decision, plus the bounded-retention prune) grow this file to MEASURED 40_692. Never lower the 39_350 floor. Ceiling 40_680 -> 40_800 (+108 headroom, lockstep). PRIOR: 2026-08-31 (#3041 pg-twin equal-instant acyclicity): the postgres structural equal-instant cycle guard `lineage_would_close_cycle_pg` (a lean id-only recursive-CTE ancestor walk to the fail-CLOSED `LINEAGE_CYCLE_CHECK_MAX_DEPTH` ceiling) + the rewired three-arm EQUAL branch in `validate_link_pre_create_pg` Pass 0 (closing the pg fail-OPEN twin of the sqlite #3041 fix, plus the >5-hop completeness gap) grow this file to MEASURED 40_575. Never lower the 39_350 floor. Ceiling 40_500 -> 40_680 (+105 headroom, lockstep). PRIOR: 2026-08-31 (#3259 pg promote to_namespace clone): the decide-only destination-STORE gate twin (`pg_refuse_unapproved_destination_store`), the pool ns-owner resolver (`pg_resolve_namespace_owner`), the cross-namespace clone (`pg_promote_to_namespace`) calling the SHARED storage helpers, and the rewired `execute_pending_action` promote arm grow this file to MEASURED 40_362. Never lower the 39_350 floor. Ceiling 40_200 -> 40_500 (+138 headroom, lockstep). PRIOR: 2026-08-30 (#3323 per-lineage token/cost accounting): `migrate_v93` (token_cost_counters DDL retrofit) + the v93 dispatch arm + the two `store`-family write hooks (`record_write_pg`) + the `recall_hybrid` hook (`record_recall_pg`) + the settled v91/v92 literal-stamp fixes grow this file to MEASURED 40_049. Never lower the 39_350 floor. Ceiling 40_050 -> 40_200 (+151 headroom, lockstep). PRIOR: 2026-08-30 (#2555 schema_version poison guard): the poison pre-check in the bootstrap downgrade guard + `migrate_v92` (pg CHECK retrofit: pg_constraint probe, out-of-band pre-flight, ADD CONSTRAINT doc-twin) + the v92 dispatch arm + the `MIGRATION_V92_SCHEMA_BOUND` const grow this file to MEASURED 39_925. Never lower the 39_350 floor. Ceiling 39_850 -> 40_050 (+125 headroom, lockstep). PRIOR: 2026-08-30 (#3172 schema-masks-data-loss gate): the postgres twin `enforce_lineage_watermarks` + `record_lineage_watermark_pg` methods and their connect-bootstrap call grow this file to MEASURED 39_753. Never lower the 39_350 floor. Ceiling 39_650 -> 39_850 (+97 headroom, lockstep). PRIOR: 2026-08-29 (B17 #3230/#3231/#3250): effective-tier expires_at CASE on both update funnels, capture_turn in-tx advisory-lock re-probe, v91 archived_memory_links CID columns + migrate_v91, grow this file to MEASURED 39_517. Never lower the 39_350 floor. Ceiling 39_500 -> 39_650 (+133 headroom). PRIOR: 2026-08-27 (#3291 SignableLink created_at): attest memory_links.created_at in the link pre-image — truncate-before-sign+INSERT in link_internal (HALT R1b S52), SELECT created_at on kg_invalidate prior-row + verify_link (all three SELECT variants), grow this file to MEASURED 39_351. Never lower the 39_350 floor. Ceiling 39_350 -> 39_500 (+149 headroom). PRIOR: 2026-08-27 (#3272/#3286 erasure primitives): C-1 unconditional namespace_meta SEVER in pg_hard_delete_in_tx, C-2 restore-only forget-tombstone clear in store_with_embedding_inner, C-3 shared pg_purge_dlq_dedup_in_tx routed from delete/evict/forget, plus three live-PG regression tests, grow this file to MEASURED 39_218. Never lower the 38_800 floor. Ceiling 39_000 -> 39_350 (+132 headroom). PRIOR: 2026-08-27 (#3270/#3271/#3275/#3296 authz cluster): the SAL caller-owns fixes add archive_restore owner predicate + delete_link owner gate + archive_by_ids rows_affected/sort + three pg regression tests, growing this file to MEASURED 38_907. Never lower the 38_800 floor from the #3235 rebase. Ceiling 38_800 -> 39_000 (+93 headroom). PRIOR (#3235 rebase onto 19892abf / #3267): postgres.rs auto-merged (boot-health cluster + pgvector preflight + SAL-parity). MEASURED 38_654 (wc -l on the resolved tree; a clean auto-merge is UNVERIFIED — always re-measure). Never lower the 37_850 floor from #3267×#3240. Ceiling 37_850 -> 38_800 (+146 headroom). PRIOR (release, #3267 x #3240): 2026-08-26 (#3267 x #3240 cross-merge re-measure): release/v1.0.0 moved again under PR #3267 — Grok\'s #3240 (pg SAL-parity cluster) grew this file to 36_999 on the release side while the #3267 review-fix wave grew it to 37_168 on the branch side; the merge of c3344757 x 0782e6ce auto-merges postgres.rs cleanly and MEASURES 37_766. Ceiling max(37_080, 37_400) -> 37_850 (+84 headroom over the merged measure). Never lower the 36_600 floor. PRIOR (PR, #3235): 2026-08-26 (#3235 rebase onto e9bf9dea): never lower. Take max(release 36_600 from #3243, PR 37_110 from #2614/#2402/#2626). PRIOR: 2026-08-25 (#3235 rebase onto 6187e189): MEASURED 37_030; ceiling 36_200 -> 37_110 (+80 headroom). */'):
        'ceiling note naming the AGE release of #3883, history',
    ('changelog.d/3297.docs.md',
     'both backends (not AGE Cypher). Re-verified on AGE **1.8.0**:'):
        'fragment of an earlier change, history',
    ('changelog.d/9927.changed.md',
     'Certified data tier (#9927): the v1.0.0 enterprise-federation tier moves to PostgreSQL 19.0 + Apache AGE 1.7.0 + pgvector 0.8.7 (operator directives c4f4d408 and 111f59db). Apache AGE 1.7.0, built from upstream PG19 branch commit c6b043d plus upstream fix commit 06ce678d (apache/age#2581) (not a tagged Apache release; upstream has no 1.7.0 release for PostgreSQL 19), is pinned by its full commit sha as `AGE_SOURCE_COMMIT` in `deploy/docker-1461/provision/lib.sh`; `Dockerfile.pg-age-vector` builds that commit plus the one pinned upstream fix (#9965) on the official PostgreSQL 19 base image pinned by digest (`PG_BASE_IMAGE`) and checks `git rev-parse HEAD`. `AGE_VERSION_CANONICAL` is now `1.7.0` (1.8.0 reports as a tested non-canonical version), the CI cert jobs require PostgreSQL 19, and every current doc states the triple with the exact provenance sentence. The PG 16 + AGE 1.6.0 alternate matrix is unchanged. The ratchet `scripts/ci/tests/test_certified_data_tier_pins.py` fails CI on any tracked file that states an earlier tier outside a marked history region or a named allowlist entry.'):
        'the PG 19 move names AGE 1.8.0 as the tested non-canonical version',
    ('scripts/ci/tests/data/certification_scope_8262_pins.json',
     '{"file": "CHANGELOG.md", "text": "- **Measured end-to-end** (two `--release --features sal-postgres` daemons, same host, same live PG 18.4 instance, interleaved to bracket drift, HTTP keep-alive, n=300): `memory_load_family` p50 **53.84 ms -> 2.59 ms (20.8x)**, p99 78.26 -> 4.17 ms. The pre-fix figure independently reproduces the 54.27 ms p50 recorded in #2580."},'):
        'pins a released CHANGELOG line, history',
    ('scripts/check-docs-vs-ssot.sh',
     '#    mentions (pgvector 0.8.2/0.8.4) and the SHIPPED-record docs'):
        'check-docs-vs-ssot names the stale forms it refuses, and its self-test plants one',
    ('scripts/check-docs-vs-ssot.sh',
     '# pgvector 0.8.5 — a true past-release record), the v1.0.0 test-campaign'):
        'check-docs-vs-ssot names the stale forms it refuses, and its self-test plants one',
    ('scripts/check-docs-vs-ssot.sh',
     '# The two-part Rust binding-crate figure (`pgvector = "0.4"`, `pgvector'):
        'the Rust binding crate pgvector 0.4, not the server extension',
    ('scripts/check-docs-vs-ssot.sh',
     "# report. (The register's F9 findings-row form `pgvector0.8.5` — no space,"):
        'check-docs-vs-ssot names the stale forms it refuses, and its self-test plants one',
    ('scripts/check-docs-vs-ssot.sh',
     '| pgvector (server extension) | **0.8.5** | `PGVECTOR_APT_VERSION=0.8.5-1.pgdg13+1` |'):
        'check-docs-vs-ssot names the stale forms it refuses, and its self-test plants one',
    ('scripts/check-docs-vs-ssot.sh',
     '| pgvector (Rust binding crate) | **0.4** | `pgvector = "0.4"` |'):
        'the Rust binding crate pgvector 0.4, not the server extension',
    ('scripts/check-docs-vs-ssot.sh',
     'The image layers pgvector 0.8.5 onto the AGE base.'):
        'check-docs-vs-ssot names the stale forms it refuses, and its self-test plants one',
    ('scripts/check-docs-vs-ssot.sh',
     'echo "FAIL: self-test — gate did NOT catch the stale pgvector patch (0.8.5 vs SSOT 0.8.7)" >&2'):
        'check-docs-vs-ssot names the stale forms it refuses, and its self-test plants one',
    ('scripts/ci/ensure-age-extension.py',
     '# #2581: no catalog read in is_age_extension_exists() outside a live transaction).  Stock 1.8.0'):
        'ensure-age-extension refuses the stock 1.8.0 build by name and digest (#8282)',
    ('scripts/ci/ensure-age-extension.py',
     '("share", "age--1.8.0.sql", "f6c2d353997a4479d1be63d0e0afc4a58fb2e0826d46f9d6d5a0e46d69441d4d"),'):
        'ensure-age-extension refuses the stock 1.8.0 build by name and digest (#8282)',
    ('scripts/ci/ensure-age-extension.py',
     '"8ecfc082a55b667ed2773d622d726bbc4ca299c0b44248a8ec7d27b1460ed927",  # stock age.dylib 1.8.0, apache/age#2580'):
        'ensure-age-extension refuses the stock 1.8.0 build by name and digest (#8282)',
    ('scripts/ci/ensure-age-extension.py',
     'REFUSED_REASON = "refused: stock apache/age 1.8.0 carries issue 2580 (issue 8282)"'):
        'ensure-age-extension refuses the stock 1.8.0 build by name and digest (#8282)',
    ('docs/compliance/v1.0.0-DECLARATION.md',
     '| `memory_recall` hot, keyword (depth 1) | PostgreSQL 18.6 + AGE 1.8.0 + pgvector 0.8.6 | 80 | 160 | 300 | 2× the SQLite row *(no pooled postgres sample on this branch; the sqlite→postgres read-lane costs one network round trip per statement)* |'):
        'measured latency row of the PG 18.6 run, a dated measurement',
    ('src/store/postgres/age_version.rs',
     'age_version_boot_warning("1.8.0"),'):
        'test that a non-canonical AGE version warns at boot',
    ('scripts/ci/tests/test_ci_base_selector_8240.py',
     'rep(SEL_JOB_ENV, SEL_JOB_ENV + "    services:\\n      db:\\n        image: postgres:19\\n")'):
        'fixture workflow text of the base selector test',
    ('docs/CONFIG_SCHEMA.md',
     '| pgvector (Rust binding crate) | **0.4** | `Cargo.toml` → `pgvector = "0.4"` |'):
        'the Rust binding crate pgvector 0.4, not the server extension',
    ('docs/enterprise-deployment.md',
     '| pgvector | **0.8.7** (`PGVECTOR_APT_VERSION=0.8.7-1.pgdg13+2`; Rust binding crate `pgvector = "0.4"`) |'):
        'the Rust binding crate pgvector 0.4, not the server extension',
    ('docs/postgres-age-guide.md',
     '| pgvector | **0.8.7** (certified) | Faster HNSW, with the upstream fix for HNSW-vacuuming index corruption. SSOT: `PGVECTOR_APT_VERSION=0.8.7-1.pgdg13+2`. **Required**: the `sal-postgres` Cargo feature pulls `dep:pgvector` (Rust binding crate `pgvector = "0.4"`) which maps Rust vectors to the Postgres `vector` column type. |'):
        'the Rust binding crate pgvector 0.4, not the server extension',
    ('scripts/ci/tests/test_pg_env_preflight_9235.py',
     'SERVER_VERSION = "16.16 (Debian 16.16-1.pgdg13+1)"'):
        'fixture of the hosted-runner PostgreSQL 16 that the coverage preflight diagnoses (#9235), not the tier',
}


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


def scan_text(rel, text, ssot, region_files=HISTORY_REGION_FILES):
    """Findings of one file. A dated history note inside a current doc sits in
    a region `tier-history: begin (<reason>)` .. `tier-history: end`; the
    region is skipped. A region in a file not in region_files, a begin
    without a reason, a nested begin, an end without a begin, an unclosed
    region, a region over the size cap and a region that holds no stale
    statement are each a finding. A YAML key without a tier word of its own
    takes the tier of the nearest enclosing parent key."""
    findings, used_lines = [], set()
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
        reasons = line_findings(line, ssot, parent_kind)
        if not reasons:
            continue
        if region is not None:
            region = (region[0], region[1] + 1)
            continue
        key = (rel, line.strip())
        if key in LINE_ALLOW:
            used_lines.add(key)
            continue
        findings.append(f"{rel}:{n}: {','.join(reasons)}: {line.strip()[:160]}")
    if region is not None:
        findings.append(f"{rel}:{region[0]}: history-region-unclosed")
    if AGE_SOURCE_NAMED.search(text) and AGE_BUILD_MAKE.search(text) and APPLIER not in text:
        findings.append(f"{rel}: age-build-without-patch")
    return findings, used_lines


def scan(root, ssot):
    findings, used_lines = [], set()
    for rel in tracked_files(root):
        if history_reason(rel):
            continue
        try:
            text, utf8 = read_file(root, rel)
        except OSError as exc:
            findings.append(f"{rel}: unreadable ({type(exc).__name__})")
            continue
        if not utf8 and rel not in BINARY_PATHS:
            findings.append(f"{rel}: non-utf8-unlisted")
        if utf8 and rel in BINARY_PATHS:
            findings.append(f"{rel}: binary-entry-is-utf8")
        found, used = scan_text(rel, text, ssot)
        findings.extend(found)
        used_lines.update(used)
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
        self.assertEqual(set(LINE_ALLOW) - self.used_lines, set(), "stale line allowlist entries")
        self.assertEqual(set(BINARY_PATHS) - files, set(), "binary entries that are not tracked")
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

HB, HE = "tier-history: begin", "tier-history: end"


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
            ("postgres:\n  version: 20\n", ["f:2: pg-binding:version=20: version: 20"]),
            ("age:\n  image: x\n  version: \"1.9.0\"\n", ['f:3: age-binding:version=1.9.0: version: "1.9.0"']),
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
             ["f:1: postgres-18: " + stale, "f:5: postgres-18: " + stale]),
        ]
        for lines, want in cases:
            self.assertEqual(scan_text("f", "\n".join(lines), SSOT_FIXTURE, {"f"})[0], want, lines)

    def test_history_region_only_in_named_files_9966(self):
        lines = [f"<!-- {HB} (dated note 2026-08-18) -->", "PostgreSQL 18.6 was certified", f"<!-- {HE} -->"]
        self.assertEqual(scan_text("g", "\n".join(lines), SSOT_FIXTURE, {"f"})[0], ["g:1: history-region-in-unlisted-file"])

    def test_age_build_must_apply_the_patch_9965(self):
        build = "git checkout ${AGE_SOURCE_COMMIT}\nmake PG_CONFIG=/usr/bin/pg_config install\n"
        self.assertEqual(scan_text("f", build, SSOT_FIXTURE, {"f"})[0], ["f: age-build-without-patch"])
        patched = build.replace("make", f"python3 {APPLIER} --ssot lib.sh --src . && make")
        self.assertEqual(scan_text("f", patched, SSOT_FIXTURE, {"f"})[0], [])

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
        return scan(self.tree, SSOT_FIXTURE)[0]

    def test_clean_tree_has_no_finding_9966(self):
        self.assertEqual(self.scan_tree(), [])

    def test_file_outside_the_first_directory_9966(self):
        (self.tree / "zzz" / "deep").mkdir(parents=True)
        (self.tree / "zzz" / "deep" / "x.toml").write_text('age_version = "1.9.0"\n')
        self.assertEqual(self.scan_tree(), ['zzz/deep/x.toml:1: age-binding:age_version=1.9.0: age_version = "1.9.0"'])

    def test_non_utf8_file_is_scanned_and_must_be_listed_9966(self):
        (self.tree / "blob.bin").write_bytes(b"\xff\xfe\x00PostgreSQL 18.6\n")
        self.assertEqual(self.scan_tree(), [
            "blob.bin: non-utf8-unlisted",
            "blob.bin:1: postgres-18: \xff\xfe\x00PostgreSQL 18.6",
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


if __name__ == "__main__":
    unittest.main()
