#!/usr/bin/env python3
# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
"""Build-script custom-build ledger gate (#2259 / #2635) — FAIL-CLOSED.

THE DEFECT CLASS THIS CLOSES (#2635). Until this rewrite the gate iterated
ONLY its own ledger:

    for record in ledger["packages"]:

The ledger held TWO packages. `cargo metadata` resolves 547, of which NINETY
carry a `custom-build` target. There was NO reverse direction — nothing walked
the resolved graph for a build script ABSENT from the ledger — so a new crate
carrying a hostile `build.rs` was never examined and the gate printed
`PASS (2 records verified)`. A list that describes itself is not an allowlist.

A cargo build script executes arbitrary code with the BUILDER's authority, at
compile time, on every CI runner and every operator machine. It is the single
highest-leverage supply-chain injection point in a Rust project, and this gate
is the mechanical enforcement of the operator's firmest standing rule — "no
external code injection. EVER." (CLAUDE.md), adopted after an external party
attempted precisely this vector, including recommending a crate that did not
yet exist on crates.io so it could be published later (a cargo-squat trap).

THE INVERSION. The gate now walks `cargo metadata` for EVERY package with a
`custom-build` target and fails closed on any package absent from the ledger.
The ledger is an ALLOWLIST THAT MUST COVER REALITY. Adding a build-script
crate — by `cargo add`, by a transitive bump, by a squat — is impossible
without a visible, dated, reviewable ledger line in the same PR.

DISPOSITIONS, and why there are two. Ninety build scripts cannot be honestly
source-audited in one change, and stamping ninety `reviewed` records on unread
source would convert an honest signal into a FALSE attestation — strictly worse
than the status quo, because a green check would then actively assert rigor
that is not present ("defaults must not lie", the repo's North Star reading).
So a record carries one of:

  * `reviewed`    — the source WAS read. Requires a dated `review_record`
                    anchor into docs/security/build-script-vetting.md AND a
                    pinned `build_dependencies` closure. Two packages today.
  * `inventoried` — present, pinned and dated, NOT source-reviewed. This is a
                    WEAKER claim, labelled as such, and it is the truthful one.

The gate never prints a bare PASS: it always reports both counts and states
what the pass does and does not attest. `inventoried` is burned down by
promotion, never by relabelling — promotion requires a review record, so a
bulk relabel is a large, loud, reviewable diff rather than a one-word edit.

THE CEILING. `inventoried_ceiling` is a monotone ratchet in the shape this repo
already runs green (`scripts/qc-allowlists/hardcoded-literals-baseline.txt`,
`required-contexts-joblevel-if-allow.txt`, `dual-trigger-cancel-allow.txt`):
the count may never exceed it, and lowering it is the only sanctioned edit. It
is the SECOND lock, and it is aimed at exactly one attack — the adversarial
lens that argued for it put it plainly: without a ceiling, landing an unvetted
build script costs a ONE-LINE APPEND that rides along unnoticed in a large PR.
With it, the same act also requires raising a number that exists for no other
purpose, in a diff whose only possible reading is "we are adding an unreviewed
build script". Dependency adds already require operator authorization
(CLAUDE.md §"Dependencies"), so a red here is not friction — it is the policy
gate firing where policy already said it must.

PINNING, per source kind. A registry package is pinned by its `Cargo.lock`
checksum. `vendor/paste` is the one package in the graph with NO source and
therefore NO lockfile checksum (it is a `path = "vendor/paste"` dependency,
#2050) — and it is simultaneously the HIGHEST-risk build script present: it is
in-tree, editable in any PR, has no upstream to diff against, and it
`Command::new($RUSTC)`s at build time. "No checksum, so skip it" would be the
same fail-open being inverted here, so a vendored record is pinned by
`tree_sha256`: a SHA-256 over every GIT-TRACKED file under `vendored_path`,
recomputed on every run. Editing `vendor/paste/build.rs` — or its `src/`, which
is a proc-macro and therefore ALSO compile-time-executed code — fails the gate.

WHAT A PASS ATTESTS: every build script in the resolved graph has an in-repo,
dated, content-pinned record, and none has changed since that record was
written. WHAT IT DOES NOT ATTEST: that the 88 `inventoried` build scripts are
safe. They execute with builder authority and have not been read.

CLI:
  scripts/check-build-script-vetting.py              — run the gate (exit 0/1)
  scripts/check-build-script-vetting.py --self-test  — plant an unvetted
      build-script package (and eight sibling defects, plus six near-miss
      shapes that must each PASS) against synthetic metadata, and assert the
      gate rejects each for the RIGHT reason. Includes the R-203 leg: the
      FROZEN pre-#2635 ledger-only algorithm is run over the same fixture and
      must return ZERO violations, so the leg cannot pass tautologically.
  scripts/check-build-script-vetting.py --update-checksums — maintenance mode:
      refresh checksums/digests of EXISTING records from the current lockfile.
      It REFUSES to add, remove or re-dispose any record, so it can service a
      routine dependency bump without ever being the thing that admits a new
      build script.

Mirrors the `--self-test` convention of the sibling gates
(scripts/check-vendor-literals.sh, scripts/check-migration-ladder.sh,
scripts/check-required-contexts.sh).
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parent.parent
LEDGER = ROOT / "supply-chain" / "build-script-vetting.json"
DOC_RECORD = "docs/security/build-script-vetting.md"

SCHEMA = 2
CUSTOM_BUILD_KIND = "custom-build"

DISPOSITION_REVIEWED = "reviewed"
DISPOSITION_INVENTORIED = "inventoried"
DISPOSITIONS = (DISPOSITION_REVIEWED, DISPOSITION_INVENTORIED)

SOURCE_REGISTRY = "registry"
SOURCE_VENDORED = "vendored"
SOURCES = (SOURCE_REGISTRY, SOURCE_VENDORED)


def package_key(package: dict[str, Any]) -> str:
    return f"{package['name']}@{package['version']}"


def has_custom_build(package: dict[str, Any]) -> bool:
    return any(CUSTOM_BUILD_KIND in target["kind"] for target in package["targets"])


# --------------------------------------------------------------------------
# Vendored-tree pinning
# --------------------------------------------------------------------------
def git_tracked_tree_sha256(root: Path, relative_path: str) -> str:
    """SHA-256 over every git-tracked file under `relative_path`.

    The boundary is GIT-TRACKED rather than "everything on disk" deliberately:
    the threat this pins is code that LANDS IN THE REPO and therefore reaches
    other builders. An untracked file cannot travel, and including it would
    make the digest depend on local scratch and produce false reds.

    Fails closed: if git is unavailable, or the path tracks no files, the
    caller gets an exception rather than a digest over nothing.
    """
    proc = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z", "--", relative_path],
        check=False,
        capture_output=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"git ls-files failed for {relative_path}: {proc.stderr.decode(errors='replace').strip()}"
        )
    names = sorted(n for n in proc.stdout.decode().split("\0") if n)
    if not names:
        raise RuntimeError(
            f"no git-tracked files under {relative_path} — refusing to digest an empty tree"
        )
    digest = hashlib.sha256()
    for name in names:
        blob = (root / name).read_bytes()
        # Length-prefix both fields so no rename/content pair can collide with
        # a different rename/content pair.
        digest.update(f"{len(name)}\0{name}\0{len(blob)}\0".encode())
        digest.update(blob)
    return digest.hexdigest()


# --------------------------------------------------------------------------
# The pure core. Everything above is I/O; everything below is a total function
# of its arguments, which is what makes --self-test able to plant fixtures
# without a network, a registry, or a mutated manifest.
# --------------------------------------------------------------------------
def verify(
    ledger: dict[str, Any],
    lock_index: dict[str, dict[str, Any]],
    metadata: dict[str, Any],
    tree_digest: Callable[[str], str],
) -> tuple[list[str], dict[str, int]]:
    """Return (violations, counts). Empty violations == the gate passes."""
    violations: list[str] = []

    def bad(message: str) -> None:
        violations.append(message)

    if ledger.get("schema") != SCHEMA:
        bad(
            f"MALFORMED LEDGER — schema is {ledger.get('schema')!r}, expected {SCHEMA}. "
            "Refusing to verify a ledger this gate does not understand (fail-closed)."
        )
        return violations, {"universe": 0, "reviewed": 0, "inventoried": 0}
    records = ledger.get("packages")
    if not isinstance(records, list):
        bad("MALFORMED LEDGER — 'packages' is not a list (fail-closed).")
        return violations, {"universe": 0, "reviewed": 0, "inventoried": 0}

    # ---- the universe: every custom-build package in the resolved graph ----
    universe = {
        package_key(p): p for p in metadata["packages"] if has_custom_build(p)
    }
    if not universe:
        bad(
            "EMPTY UNIVERSE — `cargo metadata` reported ZERO packages with a "
            "custom-build target across a graph of "
            f"{len(metadata.get('packages', []))}. That is not a clean project; it is a "
            "broken or truncated resolve. Refusing to pass (fail-closed) — a gate that "
            "verifies an empty set is the exact 'reports success while doing nothing' "
            "class this rewrite exists to end."
        )
        return violations, {"universe": 0, "reviewed": 0, "inventoried": 0}

    nodes = {n["id"]: n for n in metadata.get("resolve", {}).get("nodes", [])}
    packages_by_id = {p["id"]: p for p in metadata["packages"]}

    by_key: dict[str, dict[str, Any]] = {}
    reviewed = 0
    inventoried = 0

    for record in records:
        name = record.get("name")
        version = record.get("version")
        if not isinstance(name, str) or not isinstance(version, str):
            bad(f"MALFORMED RECORD — missing name/version: {record!r}")
            continue
        key = f"{name}@{version}"
        if key in by_key:
            bad(
                f"DUPLICATE RECORD — {key} appears twice in the ledger. Two records for one "
                "package let a reviewer read the benign one while the gate honours the other."
            )
            continue
        by_key[key] = record

        disposition = record.get("disposition")
        if disposition not in DISPOSITIONS:
            bad(
                f"MALFORMED RECORD — {key} has disposition {disposition!r}; expected one of "
                f"{list(DISPOSITIONS)}."
            )
            continue
        source = record.get("source")
        if source not in SOURCES:
            bad(
                f"MALFORMED RECORD — {key} has source {source!r}; expected one of "
                f"{list(SOURCES)}."
            )
            continue

        if disposition == DISPOSITION_REVIEWED:
            reviewed += 1
            if not record.get("review_record"):
                bad(
                    f"UNSUBSTANTIATED REVIEW — {key} is disposed '{DISPOSITION_REVIEWED}' but "
                    f"carries no 'review_record' anchor into {DOC_RECORD}. A review with no "
                    "written record is an assertion, not evidence; promoting a record without "
                    "one is exactly how a burn-down ratchet degrades into mass relabelling."
                )
            if not record.get("reviewed_on"):
                bad(
                    f"UNSUBSTANTIATED REVIEW — {key} is disposed '{DISPOSITION_REVIEWED}' but "
                    "carries no 'reviewed_on' date. An undated review cannot be aged out."
                )
            if not isinstance(record.get("build_dependencies"), list):
                bad(
                    f"MALFORMED RECORD — {key} is disposed '{DISPOSITION_REVIEWED}' but pins no "
                    "'build_dependencies' closure. The closure is the reviewed surface."
                )
        else:
            inventoried += 1
            if not record.get("first_seen"):
                bad(
                    f"MALFORMED RECORD — {key} is disposed '{DISPOSITION_INVENTORIED}' but "
                    "carries no 'first_seen' date."
                )

        # ---- stale: in the ledger, absent from the graph ------------------
        package = universe.get(key)
        if package is None:
            in_graph = any(
                package_key(p) == key for p in metadata["packages"]
            )
            if in_graph:
                bad(
                    f"STALE RECORD — {key} is in the resolved graph but NO LONGER carries a "
                    "custom-build target. Delete the record; a ledger entry for a package with "
                    "no build script is dead weight that makes the counts lie."
                )
            else:
                bad(
                    f"STALE RECORD — {key} is in the ledger but ABSENT from the resolved graph. "
                    "Delete the record in the same change that dropped the dependency."
                )
            continue

        # ---- pinning, per source kind ------------------------------------
        if source == SOURCE_REGISTRY:
            lock_package = lock_index.get(key)
            if lock_package is None:
                bad(f"{key} is recorded as a registry package but is absent from Cargo.lock.")
                continue
            if lock_package.get("checksum") != record.get("checksum"):
                bad(
                    f"CHECKSUM DRIFT — {key}: lock={lock_package.get('checksum')} "
                    f"ledger={record.get('checksum')}. The reviewed/inventoried bytes are not "
                    "the bytes that will be built."
                )
        else:
            vendored_path = record.get("vendored_path")
            if not vendored_path:
                bad(
                    f"MALFORMED RECORD — {key} is source '{SOURCE_VENDORED}' but pins no "
                    "'vendored_path'."
                )
                continue
            if package.get("source") is not None:
                bad(
                    f"SOURCE MISMATCH — {key} is recorded as '{SOURCE_VENDORED}' but the resolved "
                    f"graph gives it source {package.get('source')!r}. A registry package must "
                    "never be pinned by a tree digest — that would make 'no checksum' a "
                    "universal bypass."
                )
                continue
            try:
                actual = tree_digest(vendored_path)
            except Exception as exc:  # noqa: BLE001 — any failure is fail-closed
                bad(
                    f"VENDORED DIGEST UNCOMPUTABLE — {key} at {vendored_path}: {exc}. Refusing to "
                    "pass an unverifiable in-tree build script (fail-closed)."
                )
                continue
            if actual != record.get("tree_sha256"):
                bad(
                    f"VENDORED TREE DRIFT — {key} at {vendored_path}: "
                    f"actual={actual} ledger={record.get('tree_sha256')}. An in-tree build script "
                    "changed. Re-read the diff, then update the pin in the SAME commit."
                )

        # ---- the reviewed build-dependency closure ------------------------
        if disposition == DISPOSITION_REVIEWED and isinstance(
            record.get("build_dependencies"), list
        ):
            node = nodes.get(package["id"])
            if node is None:
                bad(
                    f"{key} has no resolve node — refusing to pass an unverifiable build-dependency "
                    "closure (fail-closed)."
                )
            else:
                actual_build_deps = sorted(
                    package_key(packages_by_id[dep["pkg"]])
                    for dep in node["deps"]
                    if any(kind.get("kind") == "build" for kind in dep["dep_kinds"])
                )
                expected = sorted(record["build_dependencies"])
                if actual_build_deps != expected:
                    bad(
                        f"BUILD-DEPENDENCY DRIFT — {key}: metadata={actual_build_deps} "
                        f"ledger={expected}. The reviewed closure changed; re-review it."
                    )

    # ---- THE INVERSION: every build script must be covered -----------------
    for key in sorted(universe):
        if key in by_key:
            continue
        package = universe[key]
        bad(
            f"UNVETTED BUILD-SCRIPT PACKAGE — {key} carries a custom-build target and has NO "
            f"record in {LEDGER.relative_to(ROOT)}. A build script executes arbitrary code with "
            "the builder's authority at compile time; it may not enter this project unexamined "
            "(CLAUDE.md: 'no external code injection. EVER.').\n"
            "     FIX: review the build script, then add the record below. Use disposition "
            f"'{DISPOSITION_REVIEWED}' with a '{DOC_RECORD}' anchor if you read the source; "
            f"'{DISPOSITION_INVENTORIED}' if you did not — and in that case ALSO raise "
            "'inventoried_ceiling' by one, which is the second, deliberate act this ledger "
            "requires of anyone admitting an unreviewed build script.\n"
            f"     {_stanza(package)}"
        )

    # ---- the monotone ratchet ---------------------------------------------
    ceiling = ledger.get("inventoried_ceiling")
    if not isinstance(ceiling, int) or ceiling < 0:
        bad(
            f"MALFORMED LEDGER — 'inventoried_ceiling' is {ceiling!r}; expected a non-negative "
            "integer. The ratchet is fail-closed: an unparseable ceiling is not an absent one."
        )
    elif inventoried > ceiling:
        bad(
            f"RATCHET — {inventoried} '{DISPOSITION_INVENTORIED}' records exceed the ceiling of "
            f"{ceiling}. This number may only ever SHRINK (thresholds tighten, never loosen). "
            "Burn it down by READING a build script and promoting its record to "
            f"'{DISPOSITION_REVIEWED}' with a {DOC_RECORD} entry — never by relabelling."
        )

    return violations, {
        "universe": len(universe),
        "reviewed": reviewed,
        "inventoried": inventoried,
        "graph": len(metadata["packages"]),
        "ceiling": ceiling if isinstance(ceiling, int) else -1,
    }


def _stanza(package: dict[str, Any]) -> str:
    """The paste-ready ledger record for an unvetted package.

    A gate whose remedy is "hand-write JSON that matches an undocumented shape"
    teaches contributors to weaken the gate instead of satisfying it.
    """
    if package.get("source") is None:
        body = {
            "name": package["name"],
            "version": package["version"],
            "source": SOURCE_VENDORED,
            "vendored_path": "vendor/<dir>",
            "tree_sha256": "<scripts/check-build-script-vetting.py --update-checksums>",
            "disposition": DISPOSITION_INVENTORIED,
            "first_seen": "<YYYY-MM-DD>",
        }
    else:
        body = {
            "name": package["name"],
            "version": package["version"],
            "source": SOURCE_REGISTRY,
            "checksum": "<the Cargo.lock checksum for this exact name@version>",
            "disposition": DISPOSITION_INVENTORIED,
            "first_seen": "<YYYY-MM-DD>",
        }
    return "RECORD: " + json.dumps(body, separators=(", ", ": "))


# --------------------------------------------------------------------------
# I/O
# --------------------------------------------------------------------------
def load_lock_index(root: Path) -> dict[str, dict[str, Any]]:
    lock = tomllib.loads((root / "Cargo.lock").read_text(encoding="utf-8"))
    return {package_key(p): p for p in lock["package"]}


def load_metadata(root: Path) -> dict[str, Any]:
    proc = subprocess.run(
        ["cargo", "metadata", "--locked", "--offline", "--format-version", "1"],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise SystemExit(
            "build-script vetting gate: FAIL: cargo metadata failed: "
            f"{proc.stderr.strip()}"
        )
    return json.loads(proc.stdout)


def report(violations: list[str], counts: dict[str, int]) -> int:
    for message in violations:
        print(f"build-script vetting gate: FAIL: {message}", file=sys.stderr)
    if violations:
        print(
            f"build-script vetting gate: FAILED with {len(violations)} violation(s). "
            f"Ledger: {LEDGER.relative_to(ROOT)}   Records: {DOC_RECORD}   "
            "Self-test: scripts/check-build-script-vetting.py --self-test",
            file=sys.stderr,
        )
        return 1
    print(
        "build-script vetting gate: PASS "
        f"({counts['universe']}/{counts['universe']} custom-build packages ledgered "
        f"out of {counts['graph']} resolved) — "
        f"{counts['reviewed']} SOURCE-REVIEWED, "
        f"{counts['inventoried']} INVENTORIED-NOT-REVIEWED (ceiling {counts['ceiling']}). "
        "Attests: every build script in the graph has a dated, content-pinned in-repo record "
        "and none has drifted. Does NOT attest that the inventoried build scripts are safe — "
        "they execute with builder authority and have not been read."
    )
    return 0


def main() -> int:
    ledger = json.loads(LEDGER.read_text(encoding="utf-8"))
    metadata = load_metadata(ROOT)
    lock_index = load_lock_index(ROOT)
    violations, counts = verify(
        ledger, lock_index, metadata, lambda p: git_tracked_tree_sha256(ROOT, p)
    )
    return report(violations, counts)


# --------------------------------------------------------------------------
# --update-checksums — maintenance mode
# --------------------------------------------------------------------------
def update_checksums() -> int:
    """Refresh pins of EXISTING records. Never adds, removes or re-disposes.

    A routine dependency bump moves the checksums of build-script crates that
    are already ledgered and already dispositioned. Hand-editing dozens of hex
    strings is the pressure that gets a gate weakened, so this exists — but it
    is deliberately incapable of admitting a NEW build script, which is the one
    act that must always be a human decision.
    """
    ledger = json.loads(LEDGER.read_text(encoding="utf-8"))
    lock_index = load_lock_index(ROOT)
    changed = 0
    for record in ledger.get("packages", []):
        key = f"{record.get('name')}@{record.get('version')}"
        if record.get("source") == SOURCE_VENDORED:
            digest = git_tracked_tree_sha256(ROOT, record["vendored_path"])
            if record.get("tree_sha256") != digest:
                record["tree_sha256"] = digest
                changed += 1
            continue
        lock_package = lock_index.get(key)
        if lock_package is None:
            print(
                f"build-script vetting gate: --update-checksums: {key} is absent from Cargo.lock; "
                "leaving the record untouched so the gate still reports it as STALE.",
                file=sys.stderr,
            )
            continue
        if record.get("checksum") != lock_package.get("checksum"):
            record["checksum"] = lock_package.get("checksum")
            changed += 1
    LEDGER.write_text(json.dumps(ledger, indent=2) + "\n", encoding="utf-8")
    print(
        f"build-script vetting gate: --update-checksums refreshed {changed} pin(s). "
        "It cannot add, remove or re-dispose a record — run the gate to see what is still missing."
    )
    return 0


# --------------------------------------------------------------------------
# --self-test
# --------------------------------------------------------------------------
def _prefix_2635_verify(
    ledger: dict[str, Any],
    lock_index: dict[str, dict[str, Any]],
    metadata: dict[str, Any],
) -> list[str]:
    """The FROZEN pre-#2635 algorithm, preserved verbatim in shape.

    It exists for one purpose: the R-203 leg. A self-test that only asserts
    "the new gate rejects the fixture" cannot distinguish a gate that closed
    the defect from a gate that was never open. Running the OLD algorithm over
    the SAME fixture and requiring it to return ZERO violations proves the
    fixture really does carry the defect and the old code really did miss it.
    """
    out: list[str] = []
    packages = {package_key(p): p for p in metadata["packages"]}
    for record in ledger["packages"]:
        key = f"{record['name']}@{record['version']}"
        lock_package = lock_index.get(key)
        if lock_package is None:
            out.append(f"recorded package {key} is absent from Cargo.lock")
            continue
        if lock_package.get("checksum") != record.get("checksum"):
            out.append(f"{key} checksum drift")
        if key not in packages:
            out.append(f"recorded package {key} is absent from the resolved graph")
    return out


def _pkg(name: str, version: str, *, build: bool, source: str | None = "registry+x") -> dict[str, Any]:
    targets = [{"kind": ["lib"], "name": name}]
    if build:
        targets.append({"kind": [CUSTOM_BUILD_KIND], "name": "build-script-build"})
    return {
        "name": name,
        "version": version,
        "id": f"{name}#{version}",
        "source": source,
        "targets": targets,
    }


def _fixture() -> tuple[dict[str, Any], dict[str, dict[str, Any]], dict[str, Any]]:
    """A synthetic universe carrying every shape the rules must discriminate."""
    packages = [
        _pkg("audited", "1.0.0", build=True),
        _pkg("noted", "2.0.0", build=True),
        # NEAR MISS: no build script. Absent from the ledger and must stay legal.
        _pkg("plain-library", "3.0.0", build=False),
        # NEAR MISS: a proc-macro is not a custom-build target.
        {
            "name": "macro-only",
            "version": "4.0.0",
            "id": "macro-only#4.0.0",
            "source": "registry+x",
            "targets": [{"kind": ["proc-macro"], "name": "macro-only"}],
        },
        # NEAR MISS: vendored, no checksum, pinned by tree digest instead.
        _pkg("vendored-thing", "5.0.0", build=True, source=None),
    ]
    metadata = {
        "packages": packages,
        "resolve": {
            "nodes": [
                {"id": "audited#1.0.0", "deps": [
                    {"pkg": "noted#2.0.0", "dep_kinds": [{"kind": "build"}]},
                ]},
                {"id": "noted#2.0.0", "deps": []},
                {"id": "vendored-thing#5.0.0", "deps": []},
                {"id": "plain-library#3.0.0", "deps": []},
                {"id": "macro-only#4.0.0", "deps": []},
            ]
        },
    }
    lock_index = {
        "audited@1.0.0": {"name": "audited", "version": "1.0.0", "checksum": "aa"},
        "noted@2.0.0": {"name": "noted", "version": "2.0.0", "checksum": "bb"},
        "plain-library@3.0.0": {"name": "plain-library", "version": "3.0.0", "checksum": "cc"},
        "macro-only@4.0.0": {"name": "macro-only", "version": "4.0.0", "checksum": "dd"},
        "vendored-thing@5.0.0": {"name": "vendored-thing", "version": "5.0.0"},
    }
    ledger = {
        "schema": SCHEMA,
        "inventoried_ceiling": 2,
        "packages": [
            {
                "name": "audited", "version": "1.0.0", "source": SOURCE_REGISTRY,
                "checksum": "aa", "disposition": DISPOSITION_REVIEWED,
                "reviewed_on": "2026-01-01", "review_record": f"{DOC_RECORD}#audited",
                "build_dependencies": ["noted@2.0.0"],
            },
            {
                "name": "noted", "version": "2.0.0", "source": SOURCE_REGISTRY,
                "checksum": "bb", "disposition": DISPOSITION_INVENTORIED,
                "first_seen": "2026-01-01",
            },
            {
                "name": "vendored-thing", "version": "5.0.0", "source": SOURCE_VENDORED,
                "vendored_path": "vendor/thing", "tree_sha256": "deadbeef",
                "disposition": DISPOSITION_INVENTORIED, "first_seen": "2026-01-01",
            },
        ],
    }
    return ledger, lock_index, metadata


def self_test() -> int:  # noqa: C901 — a flat list of legs reads better than a table
    print(
        "build-script vetting gate: self-test (clean control -> PASS; unvetted build script -> "
        "FAIL, and the FROZEN pre-#2635 algorithm must MISS it (R-203); stale record, checksum "
        "drift, vendored-tree drift, ceiling breach, unsubstantiated review, empty universe, "
        "duplicate record -> FAIL; six near-miss shapes -> PASS)"
    )

    failures: list[str] = []
    digest = lambda path: "deadbeef"  # noqa: E731 — the fixture's pinned digest

    def run(ledger, lock_index, metadata, dg=None):
        return verify(ledger, lock_index, metadata, dg or digest)

    def expect_pass(label: str, ledger, lock_index, metadata, dg=None) -> None:
        violations, _ = run(ledger, lock_index, metadata, dg)
        if violations:
            failures.append(f"[{label}] expected PASS, got: {violations}")

    def expect_fail(label: str, ledger, lock_index, metadata, needle: str,
                    forbidden: tuple[str, ...] = (), dg=None) -> None:
        violations, _ = run(ledger, lock_index, metadata, dg)
        blob = "\n".join(violations)
        if not violations:
            failures.append(f"[{label}] expected FAIL, gate passed")
            return
        if needle not in blob:
            failures.append(f"[{label}] rejected, but NOT via '{needle}' — would pass for the "
                            f"wrong reason. Got: {blob[:400]}")
        for bad_needle in forbidden:
            if bad_needle in blob:
                failures.append(f"[{label}] ALSO tripped '{bad_needle}' — the leg is not isolating "
                                f"the shape under test. Got: {blob[:400]}")

    # --- clean control ------------------------------------------------------
    ledger, lock_index, metadata = _fixture()
    expect_pass("clean", ledger, lock_index, metadata)

    # The clean control must also prove the gate iterates the METADATA, not the
    # ledger: the reported universe is the number of custom-build packages
    # (3), not the ledger length — which is the same number here only because
    # the ledger COVERS reality, which is the whole point.
    _, counts = run(*_fixture())
    if counts["universe"] != 3:
        failures.append(f"[clean] universe should be the 3 custom-build packages, got {counts}")
    if counts["reviewed"] != 1 or counts["inventoried"] != 2:
        failures.append(f"[clean] disposition counts wrong: {counts}")

    # --- THE DEFECT: an unvetted build script + the R-203 frozen-prefix leg --
    ledger, lock_index, metadata = _fixture()
    metadata["packages"].append(_pkg("evil-buildscript", "0.1.0", build=True))
    metadata["resolve"]["nodes"].append({"id": "evil-buildscript#0.1.0", "deps": []})
    lock_index["evil-buildscript@0.1.0"] = {
        "name": "evil-buildscript", "version": "0.1.0", "checksum": "ee",
    }
    expect_fail(
        "unvetted", ledger, lock_index, metadata,
        needle="UNVETTED BUILD-SCRIPT PACKAGE — evil-buildscript@0.1.0",
        forbidden=("STALE RECORD", "CHECKSUM DRIFT", "MALFORMED"),
    )
    prefix_violations = _prefix_2635_verify(ledger, lock_index, metadata)
    if prefix_violations:
        failures.append(
            "[R-203] the FROZEN pre-#2635 algorithm reported "
            f"{prefix_violations} on the unvetted fixture — it was supposed to MISS it, so this "
            "leg is not proving the defect was real"
        )

    # The remedy must be actionable: the failure has to carry a paste-ready record.
    violations, _ = run(ledger, lock_index, metadata)
    if '"name": "evil-buildscript"' not in "\n".join(violations):
        failures.append("[unvetted] failure carries no paste-ready RECORD stanza")

    # --- near misses that must PASS ----------------------------------------
    # (i) a non-custom-build package absent from the ledger
    ledger, lock_index, metadata = _fixture()
    metadata["packages"].append(_pkg("harmless", "9.9.9", build=False))
    metadata["resolve"]["nodes"].append({"id": "harmless#9.9.9", "deps": []})
    lock_index["harmless@9.9.9"] = {"name": "harmless", "version": "9.9.9", "checksum": "ff"}
    expect_pass("near-miss/no-build-script", ledger, lock_index, metadata)

    # (ii) a proc-macro absent from the ledger — a different target kind
    ledger, lock_index, metadata = _fixture()
    metadata["packages"].append({
        "name": "another-macro", "version": "1.2.3", "id": "another-macro#1.2.3",
        "source": "registry+x", "targets": [{"kind": ["proc-macro"], "name": "another-macro"}],
    })
    metadata["resolve"]["nodes"].append({"id": "another-macro#1.2.3", "deps": []})
    lock_index["another-macro@1.2.3"] = {"name": "another-macro", "version": "1.2.3", "checksum": "01"}
    expect_pass("near-miss/proc-macro", ledger, lock_index, metadata)

    # (iii) the inventoried disposition itself must not trip the unvetted rule
    ledger, lock_index, metadata = _fixture()
    for record in ledger["packages"]:
        if record["name"] == "audited":
            record["disposition"] = DISPOSITION_INVENTORIED
            record["first_seen"] = "2026-01-01"
    ledger["inventoried_ceiling"] = 3
    expect_pass("near-miss/all-inventoried", ledger, lock_index, metadata)

    # (iv) inventoried count strictly BELOW the ceiling is legal (burn-down)
    ledger, lock_index, metadata = _fixture()
    ledger["inventoried_ceiling"] = 5
    expect_pass("near-miss/under-ceiling", ledger, lock_index, metadata)

    # (v) a vendored record whose digest matches
    ledger, lock_index, metadata = _fixture()
    expect_pass("near-miss/vendored-clean", ledger, lock_index, metadata, dg=lambda p: "deadbeef")

    # (vi) a build-dependency closure that matches exactly
    ledger, lock_index, metadata = _fixture()
    expect_pass("near-miss/closure-clean", ledger, lock_index, metadata)

    # --- the sibling defects -----------------------------------------------
    ledger, lock_index, metadata = _fixture()
    ledger["packages"].append({
        "name": "ghost", "version": "0.0.1", "source": SOURCE_REGISTRY, "checksum": "zz",
        "disposition": DISPOSITION_INVENTORIED, "first_seen": "2026-01-01",
    })
    ledger["inventoried_ceiling"] = 3
    expect_fail("stale", ledger, lock_index, metadata,
                needle="STALE RECORD — ghost@0.0.1 is in the ledger but ABSENT")

    ledger, lock_index, metadata = _fixture()
    lock_index["noted@2.0.0"]["checksum"] = "TAMPERED"
    expect_fail("checksum-drift", ledger, lock_index, metadata, needle="CHECKSUM DRIFT — noted@2.0.0")

    ledger, lock_index, metadata = _fixture()
    expect_fail("vendored-drift", ledger, lock_index, metadata,
                needle="VENDORED TREE DRIFT — vendored-thing@5.0.0",
                dg=lambda p: "0000000000")

    ledger, lock_index, metadata = _fixture()
    expect_fail("vendored-uncomputable", ledger, lock_index, metadata,
                needle="VENDORED DIGEST UNCOMPUTABLE",
                dg=lambda p: (_ for _ in ()).throw(RuntimeError("no such tree")))

    # A registry package may NEVER be pinned by a tree digest — otherwise
    # "declare it vendored" becomes a universal checksum bypass.
    ledger, lock_index, metadata = _fixture()
    for record in ledger["packages"]:
        if record["name"] == "noted":
            record["source"] = SOURCE_VENDORED
            record["vendored_path"] = "vendor/noted"
            record["tree_sha256"] = "deadbeef"
    expect_fail("vendored-bypass", ledger, lock_index, metadata,
                needle="SOURCE MISMATCH — noted@2.0.0")

    ledger, lock_index, metadata = _fixture()
    ledger["inventoried_ceiling"] = 1
    expect_fail("ceiling", ledger, lock_index, metadata, needle="RATCHET — 2 'inventoried' records")

    ledger, lock_index, metadata = _fixture()
    for record in ledger["packages"]:
        if record["name"] == "noted":
            record["disposition"] = DISPOSITION_REVIEWED
            record["build_dependencies"] = []
    expect_fail("unsubstantiated-review", ledger, lock_index, metadata,
                needle="UNSUBSTANTIATED REVIEW — noted@2.0.0")

    ledger, lock_index, metadata = _fixture()
    ledger["packages"].append(dict(ledger["packages"][1]))
    expect_fail("duplicate", ledger, lock_index, metadata, needle="DUPLICATE RECORD — noted@2.0.0")

    ledger, lock_index, metadata = _fixture()
    metadata["packages"] = [_pkg("plain-library", "3.0.0", build=False)]
    expect_fail("empty-universe", ledger, lock_index, metadata, needle="EMPTY UNIVERSE")

    ledger, lock_index, metadata = _fixture()
    ledger["schema"] = 1
    expect_fail("schema", ledger, lock_index, metadata, needle="MALFORMED LEDGER — schema")

    ledger, lock_index, metadata = _fixture()
    ledger["inventoried_ceiling"] = "eighty-eight"
    expect_fail("ceiling-malformed", ledger, lock_index, metadata,
                needle="MALFORMED LEDGER — 'inventoried_ceiling'")

    # --- grounding: the REAL repo must be clean under the REAL algorithm ----
    # Without this the whole self-test could be a green parser exercise over
    # fixtures while the shipped configuration is broken.
    try:
        real_ledger = json.loads(LEDGER.read_text(encoding="utf-8"))
        real_meta = load_metadata(ROOT)
        real_lock = load_lock_index(ROOT)
        real_violations, real_counts = verify(
            real_ledger, real_lock, real_meta, lambda p: git_tracked_tree_sha256(ROOT, p)
        )
        if real_violations:
            failures.append(f"[grounding] the REAL repo does not pass: {real_violations[:2]}")
        elif real_counts["universe"] < 2:
            failures.append(
                f"[grounding] the real universe is {real_counts['universe']} custom-build "
                "packages — implausible; the metadata probe is not doing what it claims"
            )
    except SystemExit as exc:
        failures.append(f"[grounding] could not evaluate the real repo: {exc}")

    if failures:
        for line in failures:
            print(f"  ❌ {line}", file=sys.stderr)
        print(
            f"build-script vetting gate: SELF-TEST FAILED ({len(failures)} leg(s)) — the gate is "
            "NOT load-bearing until these pass.",
            file=sys.stderr,
        )
        return 1
    print("build-script vetting gate: self-test PASSED (all legs, including the R-203 frozen-prefix leg)")
    return 0


if __name__ == "__main__":
    arg = sys.argv[1] if len(sys.argv) > 1 else ""
    if arg == "--self-test":
        raise SystemExit(self_test())
    if arg == "--update-checksums":
        raise SystemExit(update_checksums())
    if arg:
        print(f"usage: {sys.argv[0]} [--self-test|--update-checksums]", file=sys.stderr)
        raise SystemExit(2)
    raise SystemExit(main())
